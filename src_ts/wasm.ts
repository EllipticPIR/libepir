
import { epir_t } from './epir_t';
import EPIRWorker from './wasm.worker.ts';

const time = () => new Date().getTime();

export const MMAX_MOD = 24;
export const MMAX = 1 << MMAX_MOD;
export const MG_SIZE = 36;
export const MG_P3_SIZE = 4 * 40;

const store_uint32_t = (wasm: any , offset: number, n: number) => {
	for(let i=0; i<4; i++) {
		wasm.HEAPU8[offset + i] = n & 0xff;
		n >>= 8;
	}
}

const store_uint64_t = (wasm: any, offset: number, n: number) => {
	for(let i=0; i<8; i++) {
		wasm.HEAPU8[offset + i] = n & 0xff;
		n >>= 8;
	}
}

const uint8ArrayConcat = (arr: Uint8Array[]) => {
	const len = arr.reduce((acc, v) => acc + v.length, 0);
	const ret = new Uint8Array(len);
	for(let i=0, offset=0; i<arr.length; i++) {
		ret.set(arr[i], offset);
		offset += arr[i].length;
	}
	return ret;
}

const uint8ArrayCompare = (a: Uint8Array, b: Uint8Array, len: number = Math.min(a.length, b.length)): number => {
	for(let i=0; i<len; i++) {
		if(a[i] == b[i]) continue;
		return a[i] - b[i];
	}
	return 0;
}

const getRandomBytes = (len: number) => {
	if(window && window.crypto && window.crypto.getRandomValues) {
		const ret = new Uint8Array(len);
		window.crypto.getRandomValues(ret);
		return ret;
	} else {
		const crypto = require('crypto');
		return crypto.randomBytes(len);
	}
};

const getRandomScalar = () => {
	const isCanonical = (buf: Uint8Array): boolean => {
		let c = (buf[31] & 0x7f) ^ 0x7f;
		for(let i=30; i>0; i--) {
			c |= buf[i] ^ 0xff;
		}
		const d = (0xed - 1 - buf[0]) >> 8;
		return !((c == 0) && d)
	};
	const isZero = (buf: Uint8Array): boolean => {
		return buf.reduce<boolean>((acc, v) => acc && (v == 0), true);
	};
	for(;;) {
		const privkey = getRandomBytes(32);
		privkey[31] &= 0x1f;
		if(!isCanonical(privkey) || isZero(privkey)) continue;
		return privkey;
	}
};

const getRandomScalars = (cnt: number) => {
	const ret: Uint8Array[] = [];
	for(let i=0; i<cnt; i++) ret.push(getRandomScalar());
	return ret;
}

type Wasm = {
	HEAPU8: {
		subarray: (begin: number, end: number) => Uint8Array;
	}
	_free: (ptr: number) => void;
};

class DecryptionContext {
	mG: Uint8Array;
	constructor(mG: Uint8Array) {
		this.mG = mG;
	}
	static load_uint32_t(buf: Uint8Array, le: boolean = false): number {
		if(le) {
			return (buf[3] * (1 << 24)) + (buf[2] << 16) + (buf[1] << 8) + buf[0];
		} else {
			return (buf[0] * (1 << 24)) + (buf[1] << 16) + (buf[2] << 8) + buf[3];
		}
	}
	load_uint32_t_from_mG(idx: number): number {
		return DecryptionContext.load_uint32_t(this.mG.subarray(36 * idx, 36 * idx + 4));
	}
	interpolationSearch(mG: Uint8Array): number {
		const mmax = this.mG.length / MG_SIZE;
		let imin = 0;
		let imax = mmax - 1;
		let left = this.load_uint32_t_from_mG(0);
		let right = this.load_uint32_t_from_mG(mmax - 1);
		const my = DecryptionContext.load_uint32_t(mG);
		for(; imin<=imax; ) {
			const imid = imin + Math.floor((imax - imin) * (my - left) / (right - left));
			const cmp = uint8ArrayCompare(this.mG.subarray(36 * imid, 36 * imid + 32), mG);
			if(cmp < 0) {
				imin = imid + 1;
				left = this.load_uint32_t_from_mG(imid);
			} else if(cmp > 0) {
				imax = imid - 1;
				right = this.load_uint32_t_from_mG(imid);
			} else {
				return DecryptionContext.load_uint32_t(this.mG.subarray(36 * imid + 32, 36 * imid + 36), true);
			}
		}
		return -1;
	}
	decrypt(wasm: any, privkey: Uint8Array, cipher: Uint8Array): number {
		const privkey_ = wasm._malloc(32);
		wasm.HEAPU8.set(privkey, privkey_);
		const cipher_ = wasm._malloc(64);
		wasm.HEAPU8.set(cipher, cipher_);
		wasm._epir_ecelgamal_decrypt_to_mG(privkey_, cipher_);
		const mG = wasm.HEAPU8.subarray(cipher_, cipher_ + 32);
		const decrypted = this.interpolationSearch(mG);
		wasm._free(privkey_);
		wasm._free(cipher_);
		return decrypted;
	}
	async decryptMany(
		ciphers: Uint8Array, privkey: Uint8Array, packing: number, nThreads: number = navigator.hardwareConcurrency):
		Promise<Uint8Array> {
		const ciphersCount = ciphers.length / 64;
		const workers: EPIRWorker[] = [];
		for(let t=0; t<nThreads; t++) workers.push(new EPIRWorker());
		const mGs = await Promise.all(workers.map((worker, i): Promise<Uint8Array> => {
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
				const ciphersMy = ciphers.subarray(begin * 64, end * 64);
				worker.postMessage({
					method: 'decrypt_mG_many', ciphers: ciphersMy, privkey: privkey,
				});
			});
		}));
		const ms: number[] = [];
		for(const mG of mGs) {
			for(let i=0; 32*i<mG.length; i++) {
				ms.push(this.interpolationSearch(mG.subarray(i * 32, (i + 1) * 32)));
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
		return decrypted;
	}
}

export const createEpir = async (): Promise<epir_t<DecryptionContext>> => {
	
	const wasm_ = require('../dist/libepir.js');
	const wasm = await wasm_();
	
	const create_privkey = (): Uint8Array => {
		return getRandomScalar();
	};
	
	const pubkey_from_privkey = (privkey: Uint8Array): Uint8Array => {
		const privkey_ = wasm._malloc(32);
		wasm.HEAPU8.set(privkey, privkey_);
		const pubkey_ = wasm._malloc(32);
		wasm._epir_pubkey_from_privkey(pubkey_, privkey_);
		const pubkey = wasm.HEAPU8.slice(pubkey_, pubkey_ + 32);
		wasm._free(pubkey_);
		wasm._free(privkey_);
		return pubkey;
	};
	
	const encrypt_ = (
		key: Uint8Array, msg: number, r: Uint8Array | undefined,
		encrypt: (cipher_: number, key_: number, msgL: number, msgH: number, r_: number) => void): Uint8Array => {
		const key_ = wasm._malloc(32);
		wasm.HEAPU8.set(key, key_);
		const cipher_ = wasm._malloc(64);
		const rr = r ? r : getRandomScalar();
		const rr_ = wasm._malloc(32);
		wasm.HEAPU8.set(rr, rr_);
		encrypt(cipher_, key_, msg&0xffffffff, Math.floor(msg/0x100000000), rr_);
		wasm._free(rr_);
		const cipher = wasm.HEAPU8.slice(cipher_, cipher_ + 64);
		wasm._free(key_);
		wasm._free(cipher_);
		return cipher;
	};
	
	const encrypt = (pubkey: Uint8Array, msg: number, r?: Uint8Array): Uint8Array => {
		return encrypt_(pubkey, msg, r, wasm._epir_ecelgamal_encrypt);
	};
	
	const encrypt_fast = (privkey: Uint8Array, msg: number, r?: Uint8Array): Uint8Array => {
		return encrypt_(privkey, msg, r, wasm._epir_ecelgamal_encrypt_fast);
	};
	
	const mg_generate_prepare = (nThreads: number, mmax: number, cb: undefined | ((p: number) => void)) => {
		const CTX_SIZE = 124;
		const ctx_ = wasm._malloc(CTX_SIZE);
		store_uint32_t(wasm, ctx_, mmax);
		const mG_ = wasm._malloc(nThreads * MG_SIZE);
		const mG_p3_ = wasm._malloc(nThreads * MG_P3_SIZE);
		let pointsComputed = 0;
		const cb_ = wasm.addFunction((data: any) => {
			if(cb) cb(++pointsComputed);
		}, 'vi');
		wasm._epir_mG_generate_prepare(ctx_, mG_, mG_p3_, nThreads, cb_, null);
		wasm.removeFunction(cb_);
		const ctx = wasm.HEAPU8.slice(ctx_, ctx_ + CTX_SIZE);
		const mG = wasm.HEAPU8.slice(mG_, mG_ + nThreads * MG_SIZE);
		const mG_p3 = wasm.HEAPU8.slice(mG_p3_, mG_p3_ + nThreads * MG_P3_SIZE);
		wasm._free(ctx_);
		wasm._free(mG_);
		wasm._free(mG_p3_);
		return { ctx: ctx, mG: mG, mG_p3: mG_p3 };
	};
	
	const mg_generate = async (mG_: number, cb: undefined | ((p: number) => void), mmax: number): Promise<void> => {
		// XXX: not working for navigator.hardwareConcurrency.
		const nThreads = navigator.hardwareConcurrency / 2;
		const workers: EPIRWorker[] = [];
		for(let i=0; i<nThreads; i++) {
			workers.push(new EPIRWorker());
		}
		const mG: Uint8Array[] = [];
		const beginCompute = time();
		const prepare = mg_generate_prepare(nThreads, mmax, cb);
		for(let t=0; t<nThreads; t++) {
			mG.push(prepare.mG.subarray(t * MG_SIZE, (t + 1) * MG_SIZE));
		}
		let pointsComputed = nThreads;
		const promises = workers.map(async (worker, workerId) => {
			return new Promise<void>((resolve, reject) => {
				worker.onmessage = (ev) => {
					switch(ev.data.method) {
						case 'mg_generate_cb':
							if(cb) cb(++pointsComputed);
							break;
						case 'mg_generate_compute':
							//console.log(`mg_generate_compute (workerId = ${workerId}) DONE.`);
							for(let i=0; i*MG_SIZE<ev.data.mG.length; i++) {
								mG.push(ev.data.mG.subarray(i * MG_SIZE, (i + 1) * MG_SIZE));
							}
							resolve();
							break;
					}
				};
				workers[workerId].postMessage({
					method: 'mg_generate_compute', nThreads: nThreads, mmax: mmax,
					ctx: prepare.ctx, mG_p3: prepare.mG_p3.slice(MG_P3_SIZE * workerId, MG_P3_SIZE * (workerId + 1)),
					threadId: workerId,
				});
			});
		});
		await Promise.all(promises);
		//console.log(`Computation done in ${(time() - beginCompute).toLocaleString()}ms.`);
		//console.log('Sorting...');
		const beginSort = time();
		mG.sort((a, b) => {
			return uint8ArrayCompare(a, b, 32);
		});
		//console.log(`Sorting done in ${(time() - beginSort).toLocaleString()}ms.`);
		for(let i=0; i<mmax; i++) {
			wasm.HEAPU8.set(mG[i], mG_ + i * MG_SIZE);
		}
	}
	
	const get_mG = async (param: undefined | string | ((p: number) => void), mmax: number): Promise<Uint8Array> => {
		if(typeof param == 'string') {
			return new Uint8Array(await require('fs/promises').readFile(param));
		} else {
			const mG_ = wasm._malloc(MG_SIZE * mmax);
			await mg_generate(mG_, param, mmax);
			const mG = wasm.HEAPU8.slice(mG_, mG_ + MG_SIZE * mmax);
			wasm._free(mG_);
			return mG;
		}
	};
	
	const get_decryption_context = async (
		param?: string | Uint8Array | ((p: number) => void), mmax: number = MMAX): Promise<DecryptionContext> => {
		const mG = (param instanceof Uint8Array ? param : await get_mG(param, mmax));
		return new DecryptionContext(mG);
	};
	
	const decrypt = (ctx: DecryptionContext, privkey: Uint8Array, cipher: Uint8Array) => {
		const decrypted = ctx.decrypt(wasm, privkey, cipher);
		if(decrypted < 0) throw new Error('Failed to decrypt.');
		return decrypted;
	};
	
	const malloc_index_counts = (index_counts: number[]): number => {
		const ic_ = wasm._malloc(8 * index_counts.length);
		for(let i=0; i<index_counts.length; i++) {
			store_uint64_t(wasm, ic_ + 8 * i, index_counts[i]);
		}
		return ic_;
	};
	
	const ciphers_or_elements_count = (index_counts: number[], count: (ic_: number, size: number) => number): number => {
		const ic_ = malloc_index_counts(index_counts);
		const c = count(ic_, index_counts.length);
		wasm._free(ic_);
		return c;
	};
	
	const ciphers_count = (index_counts: number[]): number => {
		return ciphers_or_elements_count(index_counts, wasm._epir_selector_ciphers_count);
	};
	
	const elements_count = (index_counts: number[]): number => {
		return ciphers_or_elements_count(index_counts, wasm._epir_selector_elements_count);
	};
	
	const create_choice = (index_counts: number[], idx: number): Uint8Array => {
		const ic_ = wasm._malloc(8 * index_counts.length);
		for(let i=0; i<index_counts.length; i++) {
			store_uint64_t(wasm, ic_ + 8 * i, index_counts[i]);
		}
		const ciphers = wasm._epir_selector_ciphers_count(ic_, index_counts.length);
		const selector_ = wasm._malloc(64 * ciphers);
		wasm._epir_selector_create_choice(
			selector_, ic_, index_counts.length, idx&0xffffffff, Math.floor(idx / 0xffffffff)&0xffffffff);
		const selector = wasm.HEAPU8.slice(selector_, selector_ + 64 * ciphers);
		wasm._free(selector_);
		wasm._free(ic_);
		return selector;
	};
	
	const selector_create_ = async (
		key: Uint8Array, index_counts: number[], idx: number, r: Uint8Array | undefined, isFast: boolean): Promise<Uint8Array> => {
		return new Promise(async (resolve, reject) => {
			const nThreads = navigator.hardwareConcurrency;
			const workers: EPIRWorker[] = [];
			const promises: Promise<Uint8Array>[] = [];
			const random = r ? r : getRandomBytes(ciphers_count(index_counts) * 32);
			const choice = create_choice(index_counts, idx);
			for(let t=0; t<nThreads; t++) {
				workers.push(new EPIRWorker());
				promises.push(new Promise((resolve, reject) => {
					workers[t].onmessage = (ev) => {
						switch(ev.data.method) {
							case 'selector_create':
								resolve(ev.data.selector);
								break;
						}
					};
				}));
				const ciphersPerThread = Math.ceil((choice.length / 64) / nThreads);
				const begin = t * ciphersPerThread;
				const end = Math.min((choice.length / 64) + 1, (t + 1) * ciphersPerThread);
				const choice_t = choice.subarray(begin * 64, end * 64);
				workers[t].postMessage({
					method: 'selector_create',
					choice: choice_t, key: key, random: random.subarray(begin * 32, end * 32), isFast: isFast
				});
			}
			const selectors = await Promise.all(promises);
			resolve(uint8ArrayConcat(selectors));
		});
	}
	
	const selector_create = (pubkey: Uint8Array, index_counts: number[], idx: number, r?: Uint8Array): Promise<Uint8Array> => {
		return selector_create_(pubkey, index_counts, idx, r, false);
	};
	
	const selector_create_fast = (privkey: Uint8Array, index_counts: number[], idx: number, r?: Uint8Array): Promise<Uint8Array> => {
		return selector_create_(privkey, index_counts, idx, r, true);
	};
	
	const reply_decrypt = async (
		ctx: DecryptionContext, reply: Uint8Array, privkey: Uint8Array, dimension: number, packing: number):
		Promise<Uint8Array> => {
		let midstate = reply;
		for(let phase=0; phase<dimension; phase++) {
			const decrypted = await ctx.decryptMany(midstate, privkey, packing);
			if(phase == dimension - 1) {
				midstate = decrypted;
			} else {
				midstate = decrypted.subarray(0, decrypted.length - (decrypted.length % 64));
			}
		}
		return midstate;
	};
	
	const reply_size = (dimension: number, packing: number, elem_size: number) => {
		return wasm._epir_reply_size(dimension, packing, elem_size);
	};
	
	const reply_r_count = (dimension: number, packing: number, elem_size: number) => {
		return wasm._epir_reply_r_count(dimension, packing, elem_size);
	};
	
	const reply_mock = (pubkey: Uint8Array, dimension: number, packing: number, elem: Uint8Array, r?: Uint8Array) => {
		const pubkey_ = wasm._malloc(32);
		wasm.HEAPU8.set(pubkey, pubkey_);
		const elem_ = wasm._malloc(elem.length);
		wasm.HEAPU8.set(elem, elem_);
		const rrc = reply_r_count(dimension, packing, elem.length);
		const rr = r ? r : uint8ArrayConcat(getRandomScalars(rrc));
		const rr_ = wasm._malloc(32 * rrc);
		wasm.HEAPU8.set(rr, rr_);
		const rs = reply_size(dimension, packing, elem.length);
		const reply_ = wasm._malloc(rs);
		wasm._epir_reply_mock(reply_, pubkey_, dimension, packing, elem_, elem.length, rr_);
		const reply = wasm.HEAPU8.slice(reply_, reply_ + rs);
		wasm._free(pubkey_);
		wasm._free(elem_);
		wasm._free(rr_);
		wasm._free(reply_);
		return reply;
	};
	
	return {
		create_privkey,
		pubkey_from_privkey,
		encrypt,
		encrypt_fast,
		get_decryption_context,
		decrypt,
		ciphers_count,
		elements_count,
		selector_create,
		selector_create_fast,
		reply_decrypt,
		reply_size,
		reply_r_count,
		reply_mock,
	};
	
};

