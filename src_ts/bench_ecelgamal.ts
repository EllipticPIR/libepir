
import crypto from 'crypto';

import { DEFAULT_MMAX } from './EpirBase';
import { printMeasurement } from './util';
import { createEpir, createDecryptionContext } from './addon';

export const LOOP = 10 * 1000;

export const run = async () => {
	const msgs: number[] = [];
	for(let i=0; i<LOOP; i++) {
		msgs[i] = Math.floor(Math.random() * DEFAULT_MMAX);
	}
	const epir = await createEpir();
	const decCtx = await createDecryptionContext(`${process.env['HOME']}/.EllipticPIR/mG.bin`);
	const privkey = epir.createPrivkey();
	const pubkey = epir.createPubkey(privkey);
	const encrypted = await printMeasurement<ArrayBuffer[]>(() => {
		return msgs.map((msg) => epir.encryptFast(privkey, msg));
	}, 'Ciphertext encrypted in');
	const decrypted = await printMeasurement<number[]>(() => {
		return encrypted.map((enc) => decCtx.decryptCipher(privkey, enc));
	}, 'Ciphertext encrypted in');
	for(let i=0; i<LOOP; i++) {
		if(msgs[i] !== decrypted[i]) {
			console.log('Message decrypted to a different data.');
			return false;
		}
	}
	return true;
};

if(!module.parent) {
	run();
}

