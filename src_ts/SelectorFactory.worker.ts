
import { arrayBufferConcat } from './util';
import { SCALAR_SIZE, CIPHER_SIZE } from './EpirBase';
import { LibEpirHelper, libEpirModule } from './wasm.libepir';

const worker: Worker = self as any;

interface KeyValue {
	[key: string]: (...params: any) => Promise<void>;
}
const funcs: KeyValue = {
	generateCiphers: async (
		helper: LibEpirHelper, params: { isFast: boolean, key: ArrayBuffer, msg: number, count: number, random: ArrayBuffer }) => {
		const ciphers: ArrayBuffer[] = [];
		const cipher_ = helper.malloc(CIPHER_SIZE);
		const key_ = helper.malloc(params.key);
		const r_ = helper.malloc(SCALAR_SIZE);
		for(let i=0; i<params.count; i++) {
			const encrypt = params.isFast ? 'ecelgamal_encrypt_fast' : 'ecelgamal_encrypt';
			helper.set(params.random, i * SCALAR_SIZE, SCALAR_SIZE, r_);
			helper.call(encrypt, cipher_, key_, params.msg&0xffffffff, Math.floor(params.msg/0x100000000), r_);
			const cipher = helper.slice(cipher_, CIPHER_SIZE);
			ciphers.push(cipher);
		}
		const ciphersConcat = arrayBufferConcat(ciphers);
		worker.postMessage({
			method: 'generateCiphers',
			msg: params.msg,
			ciphers: ciphersConcat,
		}, [ciphersConcat]);
		helper.free(cipher_);
		helper.free(key_);
		helper.free(r_);
	},
};

worker.onmessage = async (ev) => {
	funcs[ev.data.method](new LibEpirHelper(await libEpirModule()), ev.data.params);
};

