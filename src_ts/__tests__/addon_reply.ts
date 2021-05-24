
import {
	EpirBase,
	EpirCreateFunction,
	DecryptionContextBase,
	DecryptionContextCreateFunction,
} from '../EpirBase';
import { createEpir, createDecryptionContext } from '../addon';
import { generateRandomScalars, xorshift_init, xorshift, privkey, pubkey } from './addon';

export const runTests = (createEpir: EpirCreateFunction, createDecryptionContext: DecryptionContextCreateFunction) => {
	
	let epir: EpirBase;
	let decCtx: DecryptionContextBase;
	
	beforeAll(async () => {
		epir = await createEpir();
		decCtx = await createDecryptionContext(`${process.env['HOME']}/.EllipticPIR/mG.bin`);
	});
	
	describe('Reply', () => {
		const DIMENSION = 3;
		const PACKING = 3;
		const ELEM_SIZE = 32;
		
		const generateElem = () => {
			xorshift_init();
			const elem = new Uint8Array(ELEM_SIZE);
			for(let i=0; i<ELEM_SIZE; i++) {
				elem[i] = xorshift() & 0xff;
			}
			return elem.buffer;
		};
		
		test('get a reply size', () => {
			expect(epir.computeReplySize(DIMENSION, PACKING, ELEM_SIZE)).toBe(320896);
		});
		
		test('get a reply random count', () => {
			expect(epir.computeReplyRCount(DIMENSION, PACKING, ELEM_SIZE)).toBe(5260);
		});
		
		test('decrypt a reply (deterministic, success)', async () => {
			const elem = generateElem();
			const reply_r_count = epir.computeReplyRCount(DIMENSION, PACKING, ELEM_SIZE);
			const reply = epir.computeReplyMock(pubkey.buffer, DIMENSION, PACKING, elem, generateRandomScalars(reply_r_count));
			const decrypted = await decCtx.decryptReply(privkey.buffer, DIMENSION, PACKING, reply);
			expect(decrypted.slice(0, ELEM_SIZE)).toEqual(elem);
		});
		
		test('decrypt a reply (random, success)', async () => {
			const elem = generateElem();
			const reply = epir.computeReplyMock(pubkey.buffer, DIMENSION, PACKING, elem);
			const decrypted = await decCtx.decryptReply(privkey.buffer, DIMENSION, PACKING, reply);
			expect(decrypted.slice(0, ELEM_SIZE)).toEqual(elem);
		});
		
		test('decrypt a reply (random, fail)', async () => {
			const elem = generateElem();
			const reply = epir.computeReplyMock(pubkey.buffer, DIMENSION, PACKING, elem);
			await expect(decCtx.decryptReply(pubkey.buffer, DIMENSION, PACKING, reply)).rejects.toThrow(/^Failed to decrypt\.$/);
		});
	});
	
};

if(require.main === null) {
	runTests(createEpir, createDecryptionContext);
}

