
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
	CIPHER_SIZE
} from './EpirBase';
import { time, arrayBufferConcat, arrayBufferCompare, getRandomScalar, getRandomScalarsConcat } from './util';
import EPIRWorker from './wasm.worker.ts';

export const MG_SIZE = 36;
export const MG_P3_SIZE = 4 * 40;

import { LibEpir, LibEpirHelper } from './wasm.libepir';

export class DecryptionContext implements DecryptionContextBase {
	
	workers: EPIRWorker[] = [];
	
	constructor(public helper: LibEpirHelper, public mG: ArrayBuffer, nThreads: number = navigator.hardwareConcurrency) {
		for(let t=0; t<nThreads; t++) this.workers.push(new EPIRWorker());
	}
	
	getMG(): ArrayBuffer {
		return this.mG;
	}
	
	decryptCipher(privkey: ArrayBuffer, cipher: ArrayBuffer): number {
		const cipher_ = this.helper.malloc(cipher);
		this.helper.call('ecelgamal_decrypt_to_mG', privkey, cipher_);
		const mG = this.helper.slice(cipher_, POINT_SIZE);
		const decrypted = this.interpolationSearch(mG);
		this.helper.free(cipher_);
		if(decrypted < 0) throw new Error('Failed to decrypt.');
		return decrypted;
	}
	
	async decryptReply(privkey: ArrayBuffer, dimension: number, packing: number, reply: ArrayBuffer): Promise<ArrayBuffer> {
		let midstate = reply;
		for(let phase=0; phase<dimension; phase++) {
			const decrypted = await this.decryptMany(midstate, privkey, packing);
			if(phase == dimension - 1) {
				midstate = decrypted;
			} else {
				midstate = decrypted.slice(0, decrypted.byteLength - (decrypted.byteLength % CIPHER_SIZE));
			}
		}
		return midstate;
	}
	
	static load_uint32_t(buf: ArrayBuffer, offset: number = 0, le: boolean = false): number {
		const bufView = new Uint8Array(buf, offset, 4);
		if(le) {
			return (bufView[3] * (1 << 24)) + (bufView[2] << 16) + (bufView[1] << 8) + bufView[0];
		} else {
			return (bufView[0] * (1 << 24)) + (bufView[1] << 16) + (bufView[2] << 8) + bufView[3];
		}
	}
	
	load_uint32_t_from_mG(idx: number): number {
		return DecryptionContext.load_uint32_t(this.mG, MG_SIZE * idx);
	}
	
	interpolationSearch(mG: ArrayBuffer): number {
		const mmax = this.mG.byteLength / MG_SIZE;
		let imin = 0;
		let imax = mmax - 1;
		let left = this.load_uint32_t_from_mG(0);
		let right = this.load_uint32_t_from_mG(mmax - 1);
		const my = DecryptionContext.load_uint32_t(mG);
		for(; imin<=imax; ) {
			const imid = imin + Math.floor((imax - imin) * (my - left) / (right - left));
			const cmp = arrayBufferCompare(this.mG, MG_SIZE * imid, mG, 0, POINT_SIZE);
			if(cmp < 0) {
				imin = imid + 1;
				left = this.load_uint32_t_from_mG(imid);
			} else if(cmp > 0) {
				imax = imid - 1;
				right = this.load_uint32_t_from_mG(imid);
			} else {
				return DecryptionContext.load_uint32_t(this.mG, MG_SIZE * imid + POINT_SIZE, true);
			}
		}
		return -1;
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
			if(m == -1) throw new Error('Failed to decrypt.');
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
	const mG_p3_ = helper.malloc(nThreads * MG_P3_SIZE);
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
	const ctx = helper.slice(ctx_, CTX_SIZE);
	const mG = helper.slice(mG_, nThreads * MG_SIZE);
	const mG_p3 = helper.slice(mG_p3_, nThreads * MG_P3_SIZE);
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
	const mG: Uint8Array[] = [];
	const beginCompute = time();
	const prepare = mGGeneratePrepare(helper, nThreads, mmax, cb);
	for(let t=0; t<nThreads; t++) {
		mG.push(new Uint8Array(prepare.mG, t * MG_SIZE, MG_SIZE));
	}
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
						//console.log(`mg_generate_compute (workerId = ${workerId}) DONE.`);
						resolve(ev.data.mG);
						break;
				}
			};
			workers[workerId].postMessage({
				method: 'mg_generate_compute', nThreads: nThreads, mmax: mmax,
				ctx: prepare.ctx, mG_p3: prepare.mG_p3.slice(MG_P3_SIZE * workerId, MG_P3_SIZE * (workerId + 1)),
				threadId: workerId, cbInterval: cb ? Math.max(1, Math.floor(cb.interval / nThreads)) : Number.MAX_SAFE_INTEGER,
			});
		});
	});
	(await Promise.all(promises)).map((mGResult) => {
		for(let i=0; i*MG_SIZE<mGResult.byteLength; i++) {
			mG.push(new Uint8Array(mGResult, i * MG_SIZE, MG_SIZE));
		}
	});
	for(let t=0; t<nThreads; t++) {
		delete promises[t];
	}
	//console.log(`Computation done in ${(time() - beginCompute).toLocaleString()}ms.`);
	//console.log('Sorting...');
	const beginSort = time();
	mG.sort((a, b) => {
		for(let i=0; i<POINT_SIZE; i++) {
			if(a[i] != b[i]) return a[i] - b[i];
		}
		return 0;
	});
	//console.log(`Sorting done in ${(time() - beginSort).toLocaleString()}ms.`);
	const ret = new Uint8Array(mG.length * MG_SIZE);
	for(let i=0; i<mG.length; i++) {
		ret.set(mG[i], i * MG_SIZE);
	}
	return ret.buffer;
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
		const selector_ = this.helper.malloc(CIPHER_SIZE * ciphers);
		this.helper.call('selector_create_choice',
			selector_, ic_, index_counts.length, idx&0xffffffff, Math.floor(idx / 0xffffffff)&0xffffffff);
		const selector = this.helper.slice(selector_, CIPHER_SIZE * ciphers);
		this.helper.free(selector_);
		this.helper.free(ic_);
		return selector;
	}
	
	async selector_create_(
		key: ArrayBuffer, index_counts: number[], idx: number, r: ArrayBuffer | undefined, isFast: boolean): Promise<ArrayBuffer> {
		return new Promise(async (resolve, reject) => {
			const nThreads = this.workers.length;
			const promises: Promise<ArrayBuffer>[] = [];
			const random = new Uint8Array(r ? r : getRandomScalarsConcat(this.ciphersCount(index_counts)));
			const choice = this.create_choice(index_counts, idx);
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
				const ciphersPerThread = Math.ceil((choice.byteLength / CIPHER_SIZE) / nThreads);
				const begin = t * ciphersPerThread;
				const end = Math.min((choice.byteLength / CIPHER_SIZE) + 1, (t + 1) * ciphersPerThread);
				const choice_t = choice.slice(begin * CIPHER_SIZE, end * CIPHER_SIZE);
				const random_t = random.slice(begin * SCALAR_SIZE, end * SCALAR_SIZE).buffer;
				this.workers[t].postMessage({
					method: 'selector_create',
					choice: choice_t, key: key, random: random_t, isFast: isFast
				}, [choice_t, random_t]);
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

