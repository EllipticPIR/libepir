
import crypto from 'crypto';

import { printMeasurement } from './util';
import { createEpir, createDecryptionContext } from './addon';

const DIMENSION = 3;
const PACKING = 3;
const ELEM_SIZE = 32;

(async () => {
	const epir = await createEpir();
	const decCtx = await createDecryptionContext(`${process.env['HOME']}/.EllipticPIR/mG.bin`);
	const privkey = epir.createPrivkey();
	const pubkey = epir.createPubkey(privkey);
	const elem = new Uint8Array(crypto.randomBytes(ELEM_SIZE));
	const reply = await printMeasurement<ArrayBuffer>(() => {
		return epir.computeReplyMock(pubkey, DIMENSION, PACKING, elem.buffer);
	}, 'Compute mock:');
	const decrypted = await printMeasurement<ArrayBuffer>(async () => {
		return await decCtx.decryptReply(privkey, DIMENSION, PACKING, reply);
	}, 'Decrypt reply:');
	const decryptedView = new Uint8Array(decrypted);
	for(let i=0; i<ELEM_SIZE; i++) {
		if(elem[i] != decryptedView[i]) {
			console.log('Wrong decryption result detected.');
			return;
		}
	}
})();

