
import { MG_SIZE } from './EpirBase';
import { LibEpir, LibEpirHelper, libEpirModule } from './wasm.libepir';
import { arrayBufferConcat } from './util';

const worker: Worker = self as any;

interface KeyValue {
	[key: string]: (helper: LibEpirHelper, params: any) => Promise<void>;
}
const funcs: KeyValue = {
	// For mG.bin generation.
	mg_generate_compute: async (helper: LibEpirHelper, params: { nThreads: number, mmax: number, ctx: ArrayBuffer, mG_p3: ArrayBuffer, threadId: number, cbInterval: number }) => {
		const mG_count = Math.ceil(params.mmax / params.nThreads) - 1;
		const ctx_ = helper.malloc(params.ctx);
		const mG_ = helper.malloc(mG_count * MG_SIZE);
		const mG_p3_ = helper.malloc(params.mG_p3);
		let pointsComputed = 0;
		const cb = helper.addFunction((data: any) => {
			pointsComputed++;
			if(pointsComputed % params.cbInterval == 0 || pointsComputed === mG_count) {
				worker.postMessage({ method: 'mg_generate_cb', pointsComputed: pointsComputed });
			}
		}, 'vi');
		// Run.
		helper.call('mG_generate_compute',
			ctx_, mG_, mG_count, mG_p3_, params.nThreads + params.threadId, params.nThreads, cb, null);
		helper.removeFunction(cb);
		// Sort.
		helper.call('mG_sort', mG_, mG_count);
		const mG = helper.slice(mG_, mG_count * MG_SIZE);
		helper.free(ctx_);
		helper.free(mG_);
		helper.free(mG_p3_);
		worker.postMessage({
			method: 'mg_generate_compute', mG: mG,
		}, [mG]);
	},
	// For selector creation.
	selector_create: async (helper: LibEpirHelper, params: { choices: ArrayBuffer, key: ArrayBuffer, random: ArrayBuffer, isFast: boolean }) => {
		const key_ = helper.malloc(params.key);
		const cipher_ = helper.malloc(64);
		const random_ = helper.malloc(32);
		const encryptFn = (params.isFast ? 'ecelgamal_encrypt_fast' : 'ecelgamal_encrypt');
		const choicesView = new Uint8Array(params.choices);
		const selector: ArrayBuffer[] = [];
		for(let i=0; i<params.choices.byteLength; i++) {
			helper.set(params.random, i * 32, 32, random_);
			helper.call(encryptFn, cipher_, key_, choicesView[i], 0, random_);
			selector.push(helper.slice(cipher_, 64));
		}
		const selectorConcat = arrayBufferConcat(selector);
		worker.postMessage({
			method: 'selector_create', selector: selectorConcat,
		}, [selectorConcat]);
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

worker.onmessage = async (ev) => {
	funcs[ev.data.method](new LibEpirHelper(await libEpirModule()), ev.data);
};

