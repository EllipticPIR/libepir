
import { LibEpir, libEpirModule } from './wasm.libepir';
const wasm_ = libEpirModule();

const worker: Worker = self as any;

interface KeyValue {
	[key: string]: Function;
}
const funcs: KeyValue = {
	// For mG.bin generation.
	mg_generate_compute: async (params: { nThreads: number, mmax: number, ctx: Uint8Array, mG_p3: Uint8Array, threadId: number }) => {
		const CTX_SIZE = 124;
		const MG_SIZE = 36;
		const MG_P3_SIZE = 4 * 40;
		const wasm = await wasm_;
		const mG_count = Math.ceil(params.mmax / params.nThreads) - 1;
		const ctx_ = wasm._malloc(CTX_SIZE);
		wasm.HEAPU8.set(params.ctx, ctx_);
		const mG_ = wasm._malloc(mG_count * MG_SIZE);
		const mG_p3_ = wasm._malloc(MG_P3_SIZE);
		wasm.HEAPU8.set(params.mG_p3, mG_p3_);
		const cb = wasm.addFunction((data: any) => {
			worker.postMessage({ method: 'mg_generate_cb' });
		}, 'vi');
		wasm._epir_mG_generate_compute(
			ctx_, mG_, mG_count, mG_p3_, params.nThreads + params.threadId, params.nThreads, cb, null);
		wasm.removeFunction(cb);
		const mG = new Uint8Array(wasm.HEAPU8.subarray(mG_, mG_ + mG_count * MG_SIZE));
		worker.postMessage({
			method: 'mg_generate_compute', mG: mG,
		}, [mG.buffer]);
		wasm._free(ctx_);
		wasm._free(mG_);
		wasm._free(mG_p3_);
	},
	// For selector creation.
	selector_create: async (params: { choice: Uint8Array, key: Uint8Array, random: Uint8Array, isFast: boolean }) => {
		const wasm = await wasm_;
		const key_ = wasm._malloc(32);
		wasm.HEAPU8.set(params.key, key_);
		const cipher_ = wasm._malloc(64);
		const random_ = wasm._malloc(32);
		const encrypt = (params.isFast ? wasm._epir_ecelgamal_encrypt_fast : wasm._epir_ecelgamal_encrypt);
		for(let i=0; i*64<params.choice.length; i++) {
			wasm.HEAPU8.set(params.choice.subarray(i * 64, (i + 1) * 64), cipher_);
			wasm.HEAPU8.set(params.random.subarray(i * 32, (i + 1) * 32), random_);
			encrypt(cipher_, key_, params.choice[i * 64], 0, random_);
			params.choice.set(wasm.HEAPU8.subarray(cipher_, cipher_ + 64), i * 64);
		}
		worker.postMessage({
			method: 'selector_create', selector: params.choice,
		}, [params.choice.buffer]);
		wasm._free(key_);
		wasm._free(cipher_);
		wasm._free(random_);
	},
	// For reply decryption.
	decrypt_mG_many: async (params: { ciphers: Uint8Array, privkey: Uint8Array }) => {
		const wasm = await wasm_;
		const privkey_ = wasm._malloc(32);
		wasm.HEAPU8.set(params.privkey, privkey_);
		const cipher_ = wasm._malloc(64);
		const mG = new Uint8Array(32 * (params.ciphers.length / 64));
		for(let i=0; 64*i<params.ciphers.length; i++) {
			wasm.HEAPU8.set(params.ciphers.subarray(i * 64, (i + 1) * 64), cipher_);
			wasm._epir_ecelgamal_decrypt_to_mG(privkey_, cipher_);
			mG.set(wasm.HEAPU8.subarray(cipher_, cipher_ + 32), i * 32);
		}
		worker.postMessage({
			method: 'decrypt_mG_many', mG: mG,
		}, [mG.buffer]);
		wasm._free(privkey_);
		wasm._free(cipher_);
	},
};

worker.onmessage = (ev) => {
	funcs[ev.data.method].call(null, ev.data);
};

