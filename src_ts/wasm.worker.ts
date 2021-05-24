
import { LibEpir, LibEpirHelper } from './wasm.libepir';

const worker: Worker = self as any;

interface KeyValue {
	[key: string]: (helper: LibEpirHelper, params: any) => Promise<void>;
}
const funcs: KeyValue = {
	// For mG.bin generation.
	mg_generate_compute: async (helper: LibEpirHelper, params: { nThreads: number, mmax: number, ctx: ArrayBuffer, mG_p3: ArrayBuffer, threadId: number }) => {
		const MG_SIZE = 36;
		const mG_count = Math.ceil(params.mmax / params.nThreads) - 1;
		const ctx_ = helper.malloc(params.ctx);
		const mG_ = helper.malloc(mG_count * MG_SIZE);
		const mG_p3_ = helper.malloc(params.mG_p3);
		const cb = helper.addFunction((data: any) => {
			worker.postMessage({ method: 'mg_generate_cb' });
		}, 'vi');
		helper.call('mG_generate_compute',
			ctx_, mG_, mG_count, mG_p3_, params.nThreads + params.threadId, params.nThreads, cb, null);
		helper.removeFunction(cb);
		const mG = helper.slice(mG_, mG_count * MG_SIZE);
		worker.postMessage({
			method: 'mg_generate_compute', mG: mG,
		}, [mG]);
		helper.free(ctx_);
		helper.free(mG_);
		helper.free(mG_p3_);
	},
	// For selector creation.
	selector_create: async (helper: LibEpirHelper, params: { choice: ArrayBuffer, key: ArrayBuffer, random: ArrayBuffer, isFast: boolean }) => {
		const key_ = helper.malloc(params.key);
		const cipher_ = helper.malloc(64);
		const random_ = helper.malloc(32);
		const encryptFn = (params.isFast ? 'ecelgamal_encrypt_fast' : 'ecelgamal_encrypt');
		const choiceView = new Uint8Array(params.choice);
		for(let i=0; i*64<params.choice.byteLength; i++) {
			helper.set(params.choice, i * 64, 64, cipher_);
			helper.set(params.random, i * 32, 32, random_);
			helper.call(encryptFn, cipher_, key_, choiceView[i * 64], 0, random_);
			choiceView.set(helper.subarray(cipher_, 64), i * 64);
		}
		worker.postMessage({
			method: 'selector_create', selector: choiceView.buffer,
		}, [choiceView.buffer]);
		helper.free(key_);
		helper.free(cipher_);
		helper.free(random_);
	},
	// For reply decryption.
	decrypt_mG_many: async (helper: LibEpirHelper, params: { ciphers: ArrayBuffer, privkey: ArrayBuffer }) => {
		const privkey_ = helper.malloc(params.privkey);
		const cipher_ = helper.malloc(64);
		const mG = new Uint8Array(32 * (params.ciphers.byteLength / 64));
		for(let i=0; 64*i<params.ciphers.byteLength; i++) {
			helper.set(params.ciphers, i * 64, 64, cipher_);
			helper.call('ecelgamal_decrypt_to_mG', privkey_, cipher_);
			mG.set(helper.subarray(cipher_, 32), i * 32);
		}
		worker.postMessage({
			method: 'decrypt_mG_many', mG: mG.buffer,
		}, [mG.buffer]);
		helper.free(privkey_);
		helper.free(cipher_);
	},
};

const libEpirPromise = import('./wasm.libepir').then(({ libEpirModule }) => libEpirModule());
worker.onmessage = async (ev) => {
	funcs[ev.data.method](new LibEpirHelper(await libEpirPromise), ev.data);
};

