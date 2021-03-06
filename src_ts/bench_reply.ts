
import crypto from 'crypto';

import { MG_DEFAULT_PATH } from './types';
import { printMeasurement } from './util';
import { createEpir, createDecryptionContext } from './addon';

export const DIMENSION = 3;
export const PACKING = 3;
export const ELEM_SIZE = 32;

export const run = async (): Promise<boolean> => {
	const epir = await createEpir();
	const decCtx = await createDecryptionContext(MG_DEFAULT_PATH);
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
		/* istanbul ignore if  */
		if(elem[i] != decryptedView[i]) {
			console.log('Wrong decryption result detected.');
			return false;
		}
	}
	return true;
};

/* istanbul ignore if  */
if(!module.parent) {
	run();
}

