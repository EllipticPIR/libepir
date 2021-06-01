
import { DEFAULT_MMAX, MG_DEFAULT_PATH } from './types';
import { printMeasurement } from './util';
import { createEpir, createDecryptionContext } from './addon';

export const LOOP = 10 * 1000;

export const run = async (): Promise<boolean> => {
	const msgs: number[] = [];
	for(let i=0; i<LOOP; i++) {
		msgs[i] = Math.floor(Math.random() * DEFAULT_MMAX);
	}
	const epir = await createEpir();
	const decCtx = await createDecryptionContext(MG_DEFAULT_PATH);
	const privkey = epir.createPrivkey();
	const encrypted = await printMeasurement<ArrayBuffer[]>(() => {
		return msgs.map((msg) => epir.encryptFast(privkey, msg));
	}, 'Ciphertext encrypted (fast) in');
	const decrypted = await printMeasurement<number[]>(() => {
		return encrypted.map((enc) => decCtx.decryptCipher(privkey, enc));
	}, 'Ciphertext decrypted in');
	for(let i=0; i<LOOP; i++) {
		/* istanbul ignore if  */
		if(msgs[i] !== decrypted[i]) {
			console.log('Message decrypted to a different data.');
			return false;
		}
	}
	return true;
};

/* istanbul ignore if  */
if(!module.parent) {
	run();
}

