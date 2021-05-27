
import Dexie from 'dexie';

import {
	EpirBase,
	EpirCreateFunction,
	DecryptionContextBase,
	DecryptionContextParameter,
	DecryptionContextCallback,
	DecryptionContextCallbackFunction,
	DecryptionContextCreateFunction,
	DEFAULT_MMAX,
	SCALAR_SIZE,
	POINT_SIZE,
	CIPHER_SIZE,
	MG_SIZE,
	GE25519_P3_SIZE
} from './EpirBase';
import { time, arrayBufferConcat, arrayBufferCompare, getRandomScalar, getRandomScalarsConcat } from './util';
import EPIRWorker from './wasm.worker.ts';
import { LibEpir, LibEpirHelper } from './wasm.libepir';
import { SelectorFactory } from './wasm.SelectorFactory';

export class DecryptionContext implements DecryptionContextBase {
	
	mG_: number;
	mmax: number;
	workers: EPIRWorker[] = [];
	
	constructor(public helper: LibEpirHelper, mG: ArrayBuffer, nThreads: number = navigator.hardwareConcurrency) {
		this.mG_ = helper.malloc(mG);
		this.mmax = mG.byteLength / MG_SIZE;
		for(let t=0; t<nThreads; t++) this.workers.push(new EPIRWorker());
	}
	
	//finalize() {
	//	this.helper.free(this.mG_);
	//}
	
	getMG(): ArrayBuffer {
		const ret = new ArrayBuffer(this.mmax * MG_SIZE);
		new Uint8Array(ret).set(this.helper.subarray(this.mG_, this.mmax * MG_SIZE));
		return ret;
	}
	
	decryptCipher(privkey: ArrayBuffer, cipher: ArrayBuffer): number {
		const decrypted = this.helper.call('ecelgamal_decrypt', privkey, cipher, this.mG_, this.mmax);
		if(decrypted < 0) throw new Error('Failed to decrypt.');
		return decrypted;
	}
	
	decryptReply(privkey: ArrayBuffer, dimension: number, packing: number, reply: ArrayBuffer): Promise<ArrayBuffer> {
		return new Promise(async (resolve, reject) => {
			try {
				let midstate = reply;
				for(let phase=0; phase<dimension; phase++) {
					const decrypted = await this.decryptMany(midstate, privkey, packing);
					if(phase == dimension - 1) {
						midstate = decrypted;
					} else {
						midstate = decrypted.slice(0, decrypted.byteLength - (decrypted.byteLength % CIPHER_SIZE));
					}
				}
				resolve(midstate);
			} catch(err) {
				reject(err);
			}
		});
	}
	
	interpolationSearch(find: ArrayBuffer): number {
		return this.helper.call('mG_interpolation_search', find, this.mG_, this.mmax);
	}
	
	async decryptMany(ciphers: ArrayBuffer, privkey: ArrayBuffer, packing: number): Promise<ArrayBuffer> {
		const nThreads = this.workers.length;
		const ciphersCount = ciphers.byteLength / CIPHER_SIZE;
		const mGs = await Promise.all(this.workers.map((worker, i): Promise<ArrayBuffer> => {
			return new Promise((resolve, reject) => {
				worker.onmessage = (ev) => {
					switch(ev.data.method) {
						case 'decrypt_mG_many':
							resolve(ev.data.mG);
							break;
					}
				};
				const ciphersPerThread = Math.ceil(ciphersCount / nThreads);
				const begin = i * ciphersPerThread;
				const end = Math.min(ciphersCount + 1, (i + 1) * ciphersPerThread);
				const ciphersMy = ciphers.slice(begin * CIPHER_SIZE, end * CIPHER_SIZE);
				worker.postMessage({
					method: 'decrypt_mG_many', ciphers: ciphersMy, privkey: privkey,
				}, [ciphersMy]);
			});
		}));
		const ms: number[] = [];
		for(const mG of mGs) {
			const mGView = new Uint8Array(mG);
			for(let i=0; POINT_SIZE*i<mGView.length; i++) {
				ms.push(this.interpolationSearch(mGView.slice(i * POINT_SIZE, (i + 1) * POINT_SIZE).buffer));
			}
		}
		const decrypted = new Uint8Array(packing * ciphersCount);
		for(let i=0; i<ms.length; i++) {
			const m = ms[i];
			if(m == -1) throw 'Failed to decrypt.';
			for(let p=0; p<packing; p++) {
				decrypted[i * packing + p] = (m >> (8 * p)) & 0xff;
			}
		}
		return decrypted.buffer;
	}
	
}

const mGGeneratePrepare = (helper: LibEpirHelper, nThreads: number, mmax: number, cb: undefined | DecryptionContextCallback) => {
	const CTX_SIZE = 124;
	const ctx_ = helper.malloc(CTX_SIZE);
	helper.store32(ctx_, mmax);
	const mG_ = helper.malloc(nThreads * MG_SIZE);
	const mG_p3_ = helper.malloc(nThreads * GE25519_P3_SIZE);
	if(cb) {
		let pointsComputed = 0;
		const cb_ = helper.addFunction((data: any) => {
			pointsComputed++;
			if(pointsComputed % cb.interval != 0) return;
			cb.cb(pointsComputed);
		}, 'vi');
		helper.call('mG_generate_prepare', ctx_, mG_, mG_p3_, nThreads, cb_, null);
		helper.removeFunction(cb_);
	} else {
		helper.call('mG_generate_prepare', ctx_, mG_, mG_p3_, nThreads, null, null);
	}
	// Sort.
	helper.call('mG_sort', mG_, nThreads);
	const ctx = helper.slice(ctx_, CTX_SIZE);
	const mG = helper.slice(mG_, nThreads * MG_SIZE);
	const mG_p3 = helper.slice(mG_p3_, nThreads * GE25519_P3_SIZE);
	helper.free(ctx_);
	helper.free(mG_);
	helper.free(mG_p3_);
	return { ctx: ctx, mG: mG, mG_p3: mG_p3 };
};

const mGGenerate = async (helper: LibEpirHelper, cb: undefined | DecryptionContextCallback, mmax: number): Promise<ArrayBuffer> => {
	const nThreads = navigator.hardwareConcurrency;
	const workers: EPIRWorker[] = [];
	for(let i=0; i<nThreads; i++) {
		workers.push(new EPIRWorker());
	}
	const prepare = mGGeneratePrepare(helper, nThreads, mmax, cb);
	const pointsComputed: number[] = [];
	for(let t=0; t<nThreads; t++) {
		pointsComputed[t] = 0;
	}
	let pcLastReported = cb ? Math.floor(nThreads / cb.interval) : 0;
	const promises = workers.map(async (worker, workerId) => {
		return new Promise<ArrayBuffer>((resolve, reject) => {
			worker.onmessage = (ev) => {
				switch(ev.data.method) {
					case 'mg_generate_cb':
						if(!cb) break;
						pointsComputed[workerId] = ev.data.pointsComputed;
						const pcAll = pointsComputed.reduce((acc, v) => acc + v, 0) + nThreads;
						for(; pcLastReported+cb.interval<=pcAll; pcLastReported+=cb.interval) {
							cb.cb(pcLastReported+cb.interval);
						}
						if(pcAll === mmax && pcLastReported !== mmax) {
							cb.cb(mmax);
						}
						break;
					case 'mg_generate_compute':
						resolve(ev.data.mG);
						break;
				}
			};
			workers[workerId].postMessage({
				method: 'mg_generate_compute', nThreads: nThreads, mmax: mmax,
				ctx: prepare.ctx, mG_p3: prepare.mG_p3.slice(GE25519_P3_SIZE * workerId, GE25519_P3_SIZE * (workerId + 1)),
				threadId: workerId, cbInterval: cb ? Math.max(1, Math.floor(cb.interval / nThreads)) : Number.MAX_SAFE_INTEGER,
			});
		});
	});
	const mGCounts: number[] = [];
	const mGConcat = new Uint8Array(mmax * MG_SIZE);
	mGConcat.set(new Uint8Array(prepare.mG));
	let offset = prepare.mG.byteLength;
	(await Promise.all(promises)).map((mGResult, i) => {
		mGCounts[i] = mGResult.byteLength / MG_SIZE;
		mGConcat.set(new Uint8Array(mGResult), offset);
		offset += mGResult.byteLength;
	});
	const mGConcat_ = helper.malloc(mGConcat.buffer);
	let aCount = nThreads;
	const scratch_ = helper.malloc(mGConcat.length);
	for(let i=0; i<mGCounts.length; i++) {
		helper.call('mG_merge', scratch_, mGConcat_, aCount, mGCounts[i]);
		aCount += mGCounts[i];
	}
	helper.free(scratch_);
	const ret = helper.slice(mGConcat_, mmax * MG_SIZE);
	helper.free(mGConcat_);
	return ret;
}

const getMG = async (helper: LibEpirHelper, param: undefined | string | DecryptionContextCallback, mmax: number): Promise<ArrayBuffer> => {
	if(typeof param == 'string') {
		return new Uint8Array(await require('fs').promises.readFile(param)).buffer;
	} else {
		return mGGenerate(helper, param, mmax);
	}
}

export const createDecryptionContext: DecryptionContextCreateFunction = async (
	param?: DecryptionContextParameter, mmax: number = DEFAULT_MMAX) => {
	const { libEpirModule } = await import('./wasm.libepir');
	const wasm = await libEpirModule();
	const helper = new LibEpirHelper(wasm);
	const mG = (param instanceof ArrayBuffer ? param : await getMG(helper, param, mmax));
	return new DecryptionContext(helper, mG);
};

export interface MGDatabaseElement {
	key: number;
	value: ArrayBuffer;
}

export class MGDatabase extends Dexie {
	static VERSION = 1;
	mG: Dexie.Table<MGDatabaseElement, number>;
	constructor(dbName: string) {
		super(dbName);
		this.version(MGDatabase.VERSION).stores({
			mG: 'key',
		});
		this.mG = this.table('mG');
	}
}

export const loadDecryptionContextFromIndexedDB = async (dbName: string = 'mG.bin'): Promise<DecryptionContextBase | null> => {
	const db = new MGDatabase(dbName);
	const mGDB = await db.mG.get(0);
	if(!mGDB) return null;
	return await createDecryptionContext(mGDB.value);
};

export const saveDecryptionContextToIndexedDB = async (decCtx: DecryptionContextBase, dbName: string = 'mG.bin'): Promise<void> => {
	const db = new MGDatabase(dbName);
	await db.mG.put({ key: 0, value: decCtx.getMG() });
};

export { SelectorFactory };

export class Epir implements EpirBase {
	
	workers: EPIRWorker[] = [];
	
	constructor(public helper: LibEpirHelper, nThreads: number = navigator.hardwareConcurrency) {
		this.helper = helper;
		for(let t=0; t<nThreads; t++) this.workers.push(new EPIRWorker());
	}
	
	createPrivkey(): ArrayBuffer {
		return getRandomScalar();
	}
	
	createPubkey(privkey: ArrayBuffer): ArrayBuffer {
		const pubkey_ = this.helper.malloc(POINT_SIZE);
		this.helper.call('pubkey_from_privkey', pubkey_, privkey);
		const pubkey = this.helper.slice(pubkey_, POINT_SIZE);
		this.helper.free(pubkey_);
		return pubkey;
	}
	
	encrypt_(
		key: ArrayBuffer, msg: number, r: ArrayBuffer | undefined,
		encrypt: string): ArrayBuffer {
		const cipher_ = this.helper.malloc(CIPHER_SIZE);
		this.helper.call(encrypt, cipher_, key, msg&0xffffffff, Math.floor(msg/0x100000000), r ? r : getRandomScalar());
		const cipher = this.helper.slice(cipher_, CIPHER_SIZE);
		this.helper.free(cipher_);
		return cipher;
	}
	
	encrypt(pubkey: ArrayBuffer, msg: number, r?: ArrayBuffer): ArrayBuffer {
		return this.encrypt_(pubkey, msg, r, 'ecelgamal_encrypt');
	}
	
	encryptFast(privkey: ArrayBuffer, msg: number, r?: ArrayBuffer): ArrayBuffer {
		return this.encrypt_(privkey, msg, r, 'ecelgamal_encrypt_fast');
	}
	
	ciphers_or_elements_count(index_counts: number[], count: string): number {
		const ic_ = this.helper.malloc(8 * index_counts.length);
		for(let i=0; i<index_counts.length; i++) {
			this.helper.store64(ic_ + 8 * i, index_counts[i]);
		}
		const c = this.helper.call(count, ic_, index_counts.length);
		this.helper.free(ic_);
		return c;
	}
	
	ciphersCount(index_counts: number[]): number {
		return this.ciphers_or_elements_count(index_counts, 'selector_ciphers_count');
	}
	
	elementsCount(index_counts: number[]): number {
		return this.ciphers_or_elements_count(index_counts, 'selector_elements_count');
	}
	
	create_choice(index_counts: number[], idx: number): ArrayBuffer {
		const ic_ = this.helper.malloc(8 * index_counts.length);
		for(let i=0; i<index_counts.length; i++) {
			this.helper.store64(ic_ + 8 * i, index_counts[i]);
		}
		const ciphers = this.helper.call('selector_ciphers_count', ic_, index_counts.length);
		const choices_ = this.helper.malloc(ciphers);
		this.helper.call('selector_create_choice',
			choices_, 1, ic_, index_counts.length, idx&0xffffffff, Math.floor(idx / 0xffffffff)&0xffffffff);
		const choices = this.helper.slice(choices_, ciphers);
		this.helper.free(choices_);
		this.helper.free(ic_);
		return choices;
	}
	
	async selector_create_(
		key: ArrayBuffer, index_counts: number[], idx: number, r: ArrayBuffer | undefined, isFast: boolean): Promise<ArrayBuffer> {
		return new Promise(async (resolve, reject) => {
			const nThreads = this.workers.length;
			const promises: Promise<ArrayBuffer>[] = [];
			const random = new Uint8Array(r ? r : getRandomScalarsConcat(this.ciphersCount(index_counts)));
			const choices = this.create_choice(index_counts, idx);
			for(let t=0; t<nThreads; t++) {
				promises.push(new Promise((resolve, reject) => {
					this.workers[t].onmessage = (ev) => {
						switch(ev.data.method) {
							case 'selector_create':
								resolve(ev.data.selector);
								break;
						}
					};
				}));
				const ciphersPerThread = Math.ceil(choices.byteLength / nThreads);
				const begin = t * ciphersPerThread;
				const end = Math.min(choices.byteLength + 1, (t + 1) * ciphersPerThread);
				const choices_t = choices.slice(begin, end);
				const random_t = random.slice(begin * SCALAR_SIZE, end * SCALAR_SIZE).buffer;
				this.workers[t].postMessage({
					method: 'selector_create',
					choices: choices_t, key: key, random: random_t, isFast: isFast
				}, [choices_t, random_t]);
			}
			const selectors = await Promise.all(promises);
			resolve(arrayBufferConcat(selectors));
		});
	}
	
	async createSelector(pubkey: ArrayBuffer, index_counts: number[], idx: number, r?: ArrayBuffer): Promise<ArrayBuffer> {
		return this.selector_create_(pubkey, index_counts, idx, r, false);
	}
	
	async createSelectorFast(privkey: ArrayBuffer, index_counts: number[], idx: number, r?: ArrayBuffer): Promise<ArrayBuffer> {
		return this.selector_create_(privkey, index_counts, idx, r, true);
	}
	
	// For testing.
	computeReplySize(dimension: number, packing: number, elem_size: number): number {
		return this.helper.call('reply_size', dimension, packing, elem_size);
	}
	
	computeReplyRCount(dimension: number, packing: number, elem_size: number): number {
		return this.helper.call('reply_r_count', dimension, packing, elem_size);
	}
	
	computeReplyMock(pubkey: ArrayBuffer, dimension: number, packing: number, elem: ArrayBuffer, r?: ArrayBuffer): ArrayBuffer {
		const rrc = this.computeReplyRCount(dimension, packing, elem.byteLength);
		const rs = this.computeReplySize(dimension, packing, elem.byteLength);
		const reply_ = this.helper.malloc(rs);
		this.helper.call('reply_mock', reply_, pubkey, dimension, packing, elem, elem.byteLength, r ? r : getRandomScalarsConcat(rrc));
		const reply = this.helper.slice(reply_, rs);
		this.helper.free(reply_);
		return reply;
	}
	
}

export const createEpir: EpirCreateFunction = async () => {
	const { libEpirModule } = await import('./wasm.libepir');
	const libepir = await libEpirModule();
	const helper = new LibEpirHelper(libepir);
	return new Epir(helper);
};

