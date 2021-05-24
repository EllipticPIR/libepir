
import { LibEpir, LibEpirHelper } from './wasm.libepir';

const worker: Worker = self as any;

interface KeyValue {
	[key: string]: (helper: LibEpirHelper, params: any) => Promise<void>;
}
const funcs: KeyValue = {
	// For mG.bin generation.
	mg_generate_compute: async (helper: LibEpirHelper, params: { nThreads: number, mmax: number, ctx: Uint8Array, mG_p3: Uint8Array, threadId: number }) => {
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
		}, [mG.buffer]);
		helper.free(ctx_);
		helper.free(mG_);
		helper.free(mG_p3_);
	},
	// For selector creation.
	selector_create: async (helper: LibEpirHelper, params: { choice: Uint8Array, key: Uint8Array, random: Uint8Array, isFast: boolean }) => {
		const key_ = helper.malloc(params.key);
		const cipher_ = helper.malloc(64);
		const random_ = helper.malloc(32);
		const encryptFn = (params.isFast ? 'ecelgamal_encrypt_fast' : 'ecelgamal_encrypt');
		for(let i=0; i*64<params.choice.length; i++) {
			helper.set(params.choice.subarray(i * 64, (i + 1) * 64), cipher_);
			helper.set(params.random.subarray(i * 32, (i + 1) * 32), random_);
			helper.call(encryptFn, cipher_, key_, params.choice[i * 64], 0, random_);
			params.choice.set(helper.subarray(cipher_, 64), i * 64);
		}
		worker.postMessage({
			method: 'selector_create', selector: params.choice,
		}, [params.choice.buffer]);
		helper.free(key_);
		helper.free(cipher_);
		helper.free(random_);
	},
	// For reply decryption.
	decrypt_mG_many: async (helper: LibEpirHelper, params: { ciphers: Uint8Array, privkey: Uint8Array }) => {
		const privkey_ = helper.malloc(params.privkey);
		const cipher_ = helper.malloc(64);
		const mG = new Uint8Array(32 * (params.ciphers.length / 64));
		for(let i=0; 64*i<params.ciphers.length; i++) {
			helper.set(params.ciphers.subarray(i * 64, (i + 1) * 64), cipher_);
			helper.call('ecelgamal_decrypt_to_mG', privkey_, cipher_);
			mG.set(helper.subarray(cipher_, 32), i * 32);
		}
		worker.postMessage({
			method: 'decrypt_mG_many', mG: mG,
		}, [mG.buffer]);
		helper.free(privkey_);
		helper.free(cipher_);
	},
};

const libEpirPromise = import('./wasm.libepir').then(({ libEpirModule }) => libEpirModule());
worker.onmessage = async (ev) => {
	funcs[ev.data.method](new LibEpirHelper(await libEpirPromise), ev.data);
};

