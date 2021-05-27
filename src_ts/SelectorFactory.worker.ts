
import { arrayBufferConcat } from './util';
import { EpirBase, SCALAR_SIZE, CIPHER_SIZE } from './EpirBase';
import { createEpir } from './wasm';

const worker: Worker = self as any;

interface KeyValue {
	[key: string]: (...params: any) => Promise<void>;
}
const funcs: KeyValue = {
	generateCiphers: async (
		epir: EpirBase, params: { isFast: boolean, key: ArrayBuffer, msg: number, count: number, random: ArrayBuffer }) => {
		const ciphers: ArrayBuffer[] = [];
		for(let i=0; i<params.count; i++) {
			ciphers.push(params.isFast ?
				epir.encryptFast(params.key, params.msg, params.random.slice(i * SCALAR_SIZE, (i + 1) * SCALAR_SIZE)) :
				epir.encrypt(params.key, params.msg, params.random.slice(i * SCALAR_SIZE, (i + 1) * SCALAR_SIZE)));
		}
		const ciphersConcat = arrayBufferConcat(ciphers);
		worker.postMessage({
			method: 'ciphers',
			msg: params.msg,
			ciphers: ciphersConcat,
		}, [ciphersConcat]);
		worker.postMessage({
			method: 'generateCiphers',
		});
	},
};

const epirPromise = createEpir();
worker.onmessage = async (ev) => {
	funcs[ev.data.method].call(null, await epirPromise, ev.data.params);
};

