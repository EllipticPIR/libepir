
import {
	EpirCreateFunction,
	DecryptionContextCreateFunction,
	MG_DEFAULT_PATH,
	CIPHER_SIZE,
	PACKING_MAX
} from '../types';
import { generateRandomScalars, xorshift_init, xorshift, privkey, pubkey } from './main';

export const runTests = (createEpir: EpirCreateFunction, createDecryptionContext: DecryptionContextCreateFunction): void => {
	
	const epirPromise = createEpir();
	const decCtxPromise = createDecryptionContext(MG_DEFAULT_PATH);
	
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
		
		it('get a reply size', async () => {
			const epir = await epirPromise;
			expect(epir.computeReplySize(DIMENSION, PACKING, ELEM_SIZE)).toBe(320896);
		});
		
		it('get a reply random count', async () => {
			const epir = await epirPromise;
			expect(epir.computeReplyRCount(DIMENSION, PACKING, ELEM_SIZE)).toBe(5260);
		});
		
		it('decrypt a reply (deterministic, success)', async () => {
			const epir = await epirPromise;
			const decCtx = await decCtxPromise;
			const elem = generateElem();
			const reply_r_count = epir.computeReplyRCount(DIMENSION, PACKING, ELEM_SIZE);
			const reply = epir.computeReplyMock(pubkey.buffer, DIMENSION, PACKING, elem, generateRandomScalars(reply_r_count));
			const decrypted = await decCtx.decryptReply(privkey.buffer, DIMENSION, PACKING, reply);
			expect(decrypted.slice(0, ELEM_SIZE)).toEqual(elem);
		}, 30 * 1000);
		
		it('decrypt a reply (random, success)', async () => {
			const epir = await epirPromise;
			const decCtx = await decCtxPromise;
			const elem = generateElem();
			const reply = epir.computeReplyMock(pubkey.buffer, DIMENSION, PACKING, elem);
			const decrypted = await decCtx.decryptReply(privkey.buffer, DIMENSION, PACKING, reply);
			expect(decrypted.slice(0, ELEM_SIZE)).toEqual(elem);
		}, 30 * 1000);
		
		it('decrypt a reply (random, fail)', async () => {
			const epir = await epirPromise;
			const decCtx = await decCtxPromise;
			const elem = generateElem();
			const reply = epir.computeReplyMock(pubkey.buffer, DIMENSION, PACKING, elem);
			await expect(decCtx.decryptReply(pubkey.buffer, DIMENSION, PACKING, reply)).rejects.toMatch(/^Failed to decrypt\.$/);
		}, 30 * 1000);
		
		it('reject a zero dimension when computing a reply size or a mock reply', async () => {
			const epir = await epirPromise;
			expect(() => epir.computeReplySize(0, PACKING, ELEM_SIZE)).toThrow(/dimension/);
			expect(() => epir.computeReplyRCount(0, PACKING, ELEM_SIZE)).toThrow(/dimension/);
			expect(() => epir.computeReplyMock(pubkey.buffer, 0, PACKING, generateElem(), new ArrayBuffer(0))).toThrow(/dimension/);
		});
		
		it('reject a too short randomness for a mock reply', async () => {
			const epir = await epirPromise;
			const rCount = epir.computeReplyRCount(DIMENSION, PACKING, ELEM_SIZE);
			const short = generateRandomScalars(rCount - 1);
			expect(() => epir.computeReplyMock(pubkey.buffer, DIMENSION, PACKING, generateElem(), short)).toThrow(/'r'/);
			// Exactly enough randomness is accepted.
			const reply = epir.computeReplyMock(pubkey.buffer, DIMENSION, PACKING, generateElem(), generateRandomScalars(rCount));
			expect(reply.byteLength).toBe(epir.computeReplySize(DIMENSION, PACKING, ELEM_SIZE));
		});
		
		it('reject a zero packing when computing a reply size or a mock reply', async () => {
			const epir = await epirPromise;
			expect(() => epir.computeReplySize(DIMENSION, 0, ELEM_SIZE)).toThrow();
			expect(() => epir.computeReplyRCount(DIMENSION, 0, ELEM_SIZE)).toThrow();
			expect(() => epir.computeReplyMock(pubkey.buffer, DIMENSION, 0, generateElem(), new ArrayBuffer(0))).toThrow();
		});
		
		it('reject an out-of-range packing or dimension', async () => {
			const decCtx = await decCtxPromise;
			const reply = new ArrayBuffer(CIPHER_SIZE);
			const decrypt = async (dimension: number, packing: number) => decCtx.decryptReply(privkey.buffer, dimension, packing, reply);
			for(const packing of [0, PACKING_MAX + 1, 64, 256, 256 + PACKING, -1]) {
				await expect(decrypt(DIMENSION, packing)).rejects.toThrow(/packing/);
			}
			for(const dimension of [0, 256, 256 + DIMENSION, -1]) {
				await expect(decrypt(dimension, PACKING)).rejects.toThrow(/dimension/);
			}
		});
	});
	
};

