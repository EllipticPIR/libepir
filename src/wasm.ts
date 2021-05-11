
import epir_t from './epir_t';
import EPIRWorker from 'worker-loader!./wasm.worker';

const time = () => new Date().getTime();

export const MMAX_MOD = 24;
export const MMAX = 1 << MMAX_MOD;
export const MG_SIZE = 36;
export const MG_P3_SIZE = 4 * 40;

const uint8ArrayConcat = (arr: Uint8Array[]) => {
	const len = arr.reduce((acc, v) => acc + v.length, 0);
	const ret = new Uint8Array(len);
	for(let i=0, offset=0; i<arr.length; i++) {
		ret.set(arr[i], offset);
		offset += arr[i].length;
	}
	return ret;
}

type Wasm = {
	HEAPU8: {
		subarray: (begin: number, end: number) => Uint8Array;
	}
	_free: (ptr: number) => void;
};

class DecryptionContext {
	nThreads: number;
	workers: EPIRWorker[] = [];
	mG_: number[] = [];
	mmax: number = -1;
	constructor(nThreads: number = navigator.hardwareConcurrency) {
		this.nThreads = nThreads;
		for(let i=0; i<this.nThreads; i++) {
			this.workers.push(new EPIRWorker());
		}
		this.mG_ = new Array(nThreads);
	}
	async init(mG: Uint8Array): Promise<void> {
		const mGShared = new SharedArrayBuffer(mG.length);
		new Uint8Array(mGShared).set(mG);
		this.mG_ = await Promise.all(this.workers.map((worker): Promise<number> => {
			return new Promise((resolve, reject) => {
				worker.addEventListener('message', (ev) => {
					switch(ev.data.method) {
						case 'malloc':
							resolve(ev.data.buf_);
							break;
					}
				});
				worker.postMessage({ method: 'malloc', buf: mGShared });
			});
		}));
		this.mmax = mG.length / MG_SIZE;
	}
	async delete() {
		await Promise.all(this.workers.map((worker, i): Promise<void> => {
			return new Promise((resolve, reject) => {
				worker.addEventListener('message', (ev) => {
					switch(ev.data.method) {
						case 'free':
							resolve();
							break;
					}
				});
				worker.postMessage({ method: 'free', buf_: this.mG_[i] });
			});
		}));
	}
	async decrypt(ciphers: Uint8Array, privkey: Uint8Array, packing: number): Promise<Uint8Array> {
		const decrypted = await Promise.all(this.workers.map((worker, i): Promise<Uint8Array> => {
			return new Promise((resolve, reject) => {
				worker.addEventListener('message', (ev) => {
					switch(ev.data.method) {
						case 'decrypt_many':
							resolve(ev.data.decrypted);
							break;
					}
				});
				
				const ciphersPerThread = Math.ceil((ciphers.length / 64) / this.nThreads);
				const begin = i * ciphersPerThread;
				const end = Math.min((ciphers.length / 64) + 1, (i + 1) * ciphersPerThread);
				const ciphersMy = ciphers.subarray(begin * 64, end * 64);
				worker.postMessage({
					method: 'decrypt_many', ciphers: ciphersMy , privkey: privkey, packing: packing, mG_: this.mG_[i] , mmax: this.mmax
				});
			});
		}));
		return uint8ArrayConcat(decrypted);
	}
}

export const epir = async (): Promise<epir_t<DecryptionContext>> => {
	
	const wasm_ = require('../dist/epir.js');
	const wasm = await wasm_();
	
	wasm._epir_randombytes_init();
	
	const store_uint64_t = (offset: number, n: number) => {
		for(let i=0; i<8; i++) {
			wasm.HEAPU8[offset + i] = n & 0xff;
			n >>= 8;
		}
	}
	
	const create_privkey = (): Uint8Array => {
		const privkey_ = wasm._malloc(32);
		wasm._epir_create_privkey(privkey_);
		const privkey = new Uint8Array(wasm.HEAPU8.subarray(privkey_, privkey_ + 32));
		wasm._free(privkey_);
		return privkey;
	};
	
	const pubkey_from_privkey = (privkey: Uint8Array): Uint8Array => {
		const privkey_ = wasm._malloc(32);
		wasm.HEAPU8.set(privkey, privkey_);
		const pubkey_ = wasm._malloc(32);
		wasm._epir_pubkey_from_privkey(pubkey_, privkey_);
		const pubkey = new Uint8Array(wasm.HEAPU8.subarray(pubkey_, pubkey_ + 32));
		wasm._free(pubkey_);
		wasm._free(privkey_);
		return pubkey;
	};
	
	const uint8ArrayCompare = (a: Uint8Array, b: Uint8Array): number => {
		for(let i=0; i<Math.min(a.length, b.length); i++) {
			if(a[i] == b[i]) continue;
			return a[i] - b[i];
		}
		return 0;
	}
	
	const mg_generate = async (mG_: number, cb: ((p: number) => void) | null): Promise<void> => {
		return new Promise((resolve, reject) => {
			const nThreads = 1;//navigator.hardwareConcurrency;
			const worker = new EPIRWorker();
			let mG: Uint8Array[] = [];
			worker.onmessage = (e) => {
				switch(e.data.method) {
					case 'mg_generate_cb':
						if(cb) cb(e.data.pointsComputed);
						break;
					case 'mg_generate_prepare':
						//console.log('mg_generate_prepare DONE.');
						const threadId = 0;
						for(let i=0; i<nThreads; i++) {
							mG.push(e.data.mG.slice(i * MG_SIZE, (i + 1) * MG_SIZE));
						}
						worker.postMessage({
							method: 'mg_generate_compute', nThreads: nThreads, mmax: MMAX,
							ctx: e.data.ctx, mG_p3: e.data.mG_p3.slice(MG_P3_SIZE * threadId, MG_P3_SIZE * (threadId + 1)), threadId: threadId,
						});
						break;
					case 'mg_generate_compute':
						//console.log('mg_generate_compute DONE.');
						for(let i=0; i*MG_SIZE<e.data.mG.length; i++) {
							mG.push(e.data.mG.slice(i * MG_SIZE, (i + 1) * MG_SIZE));
						}
						//console.log('Sorting...');
						const beginSort = time();
						mG.sort((a, b) => {
							return uint8ArrayCompare(a, b);
						});
						//console.log(`Sorting done in ${(time() - beginSort).toLocaleString()}ms.`);
						for(let i=0; i<MMAX; i++) {
							wasm.HEAPU8.set(mG[i], mG_ + i * MG_SIZE);
						}
						resolve();
						break;
				}
			};
			worker.postMessage({ method: 'mg_generate_prepare', nThreads: nThreads, mmax: MMAX });
		});
	}
	
	const get_mG = async (param?: string | ((p: number) => void)): Promise<Uint8Array> => {
		if(typeof param == 'string') {
			return new Uint8Array(await require('fs/promises').readFile(param));
		} else {
			const mG_ = wasm._malloc(MG_SIZE * MMAX);
			await mg_generate(mG_, param === undefined ? null : param);
			const mG = wasm.HEAPU8.slice(mG_, mG_ + MG_SIZE * MMAX);
			wasm._free(mG_);
			return mG;
		}
	};
	
	const get_decryption_context = async (param?: string | Uint8Array | ((p: number) => void)): Promise<DecryptionContext> => {
		const mG = (param instanceof Uint8Array ? param : await get_mG(param));
		const decCtx = new DecryptionContext();
		await decCtx.init(mG);
		return decCtx;
	};
	
	const selector_create_ = async (key: Uint8Array, index_counts: number[], idx: number, isFast: boolean): Promise<Uint8Array> => {
		return new Promise(async (resolve, reject) => {
			const nThreads = navigator.hardwareConcurrency;
			const workers: EPIRWorker[] = [];
			const promises: Promise<Uint8Array>[] = [];
			for(let i=0; i<nThreads; i++) {
				workers.push(new EPIRWorker());
				promises.push(new Promise((resolve, reject) => {
					workers[i].addEventListener('message', (ev) => {
						switch(ev.data.method) {
							case 'selector_create_choice':
								const ciphersPerThread = Math.ceil((ev.data.selector.length / 64) / nThreads);
								for(let t=0; t<nThreads; t++) {
									const begin = t * ciphersPerThread;
									const end = Math.min((ev.data.selector.length / 64) + 1, (t + 1) * ciphersPerThread);
									const random = new Uint8Array((end - begin) * 32);
									for(let j=0; j*32<random.length; j++) {
										const tmp = new Uint8Array(32);
										window.crypto.getRandomValues(tmp);
										random.set(tmp, j * 32);
									}
									const selector_t = ev.data.selector.subarray(begin * 64, end * 64);
									workers[t].postMessage({
										method: 'selector_create', selector: selector_t, key: key, random: random, isFast: isFast
									}, [random.buffer]);
								}
								break;
							case 'selector_create':
								resolve(ev.data.selector);
								break;
						}
					});
				}));
			}
			workers[0].postMessage({ method: 'selector_create_choice', index_counts: index_counts, idx: idx });
			const selectors = await Promise.all(promises);
			resolve(uint8ArrayConcat(selectors));
		});
	}
	
	const selector_create = (pubkey: Uint8Array, index_counts: number[], idx: number): Promise<Uint8Array> => {
		return selector_create_(pubkey, index_counts, idx, false);
	};
	
	const selector_create_fast = (privkey: Uint8Array, index_counts: number[], idx: number): Promise<Uint8Array> => {
		return selector_create_(privkey, index_counts, idx, true);
	};
	
	const reply_decrypt = async (
		ctx: DecryptionContext, reply: Uint8Array, privkey: Uint8Array, dimension: number, packing: number):
		Promise<Uint8Array> => {
		let midstate = reply;
		for(let phase=0; phase<dimension; phase++) {
			const decrypted = await ctx.decrypt(midstate, privkey, packing);
			if(phase == dimension - 1) {
				midstate = decrypted;
			} else {
				midstate = decrypted.subarray(0, decrypted.length - (decrypted.length % 64));
			}
		}
		return midstate;
	};
	
	return {
		create_privkey,
		pubkey_from_privkey,
		get_mG,
		get_decryption_context,
		selector_create,
		selector_create_fast,
		reply_decrypt,
	};
	
};

export default epir;

