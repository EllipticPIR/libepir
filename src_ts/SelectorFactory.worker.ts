
import { EpirBase, CIPHER_SIZE } from './EpirBase';

const worker: Worker = self as any;

interface KeyValue {
	[key: string]: (...params: any) => Promise<void>;
}
const funcs: KeyValue = {
	generateCiphers: async (epir: EpirBase, isFast: boolean, key: ArrayBuffer, msg: number, count: number) => {
		for(let i=0; i<count; i++) {
			const cipher = isFast ? epir.encryptFast(key, msg) : epir.encrypt(key, msg);
			worker.postMessage({
				method: 'cipher',
				msg: msg,
				cipher: cipher,
			}, [cipher]);
		}
		worker.postMessage({
			method: 'generateCiphers',
		});
	},
};

worker.onmessage = async (ev) => {
	funcs[ev.data.method].apply(null, ev.data.params);
};

