
import crypto from 'crypto';

import {
	EpirBase,
	EpirCreateFunction,
	DecryptionContextBase,
	DecryptionContextCreateFunction,
	SCALAR_SIZE,
	CIPHER_SIZE,
	MG_DEFAULT_PATH
} from '../EpirBase';
import { createEpir, createDecryptionContext } from '../addon';

export let x: number;
export let y: number;
export let z: number;
export let w: number;

export const xorshift_init = () => {
	x = 123456789;
	y = 362436069;
	z = 521288629;
	w = 88675123;
};

export const shiftL = (n: number, cnt: number) => {
	return (n * (2 ** cnt)) & 0xffffffff;
};

export const xorshift = () => {
	const t = x ^ (shiftL(x, 11));
	x = y; y = z; z = w;
	w = (w ^ (w >>> 19)) ^ (t ^ (t >>> 8));
	return w;
};

export const sha256sum = (buf: ArrayBuffer): ArrayBuffer => {
	const hash = crypto.createHash('sha256');
	hash.update(new Uint8Array(buf));
	return new Uint8Array(Buffer.from(hash.digest('hex'), 'hex'));
};

export const generateRandomScalars = (cnt: number) => {
	const r = new Uint8Array(cnt * SCALAR_SIZE);
	xorshift_init();
	for(let i=0; i<cnt; i++) {
		for(let j=0; j<SCALAR_SIZE; j++) {
			r[i * SCALAR_SIZE + j] = xorshift() & 0xff;
		}
		r[(i + 1) * SCALAR_SIZE - 1] &= 0x1f;
	}
	return r.buffer;
};

export const privkey = new Uint8Array([
	0x7e, 0xf6, 0xad, 0xd2, 0xbe, 0xd5, 0x9a, 0x79,
	0xba, 0x6e, 0xdc, 0xfb, 0xa4, 0x8f, 0xde, 0x7a,
	0x55, 0x31, 0x75, 0x4a, 0xf5, 0x93, 0x76, 0x34,
	0x6c, 0x8b, 0x52, 0x84, 0xee, 0xf2, 0x52, 0x07
]);

export const pubkey = new Uint8Array([
	0x9c, 0x76, 0x82, 0x3d, 0xbd, 0xb9, 0xbf, 0x04,
	0x8f, 0xc5, 0xc2, 0xaf, 0x00, 0x0e, 0x28, 0xa1,
	0x48, 0xee, 0x02, 0x19, 0x99, 0xfb, 0x7f, 0x21,
	0xca, 0x1f, 0x84, 0xb8, 0xfe, 0x73, 0xd7, 0xe8
]);

export const msg = 0x12345678 & ((1 << 24) - 1);

export const r = new Uint8Array([
	0x42, 0xff, 0x2d, 0x98, 0x4a, 0xe5, 0xa2, 0x8f,
	0x7d, 0x02, 0x69, 0x87, 0xc7, 0x10, 0x9a, 0x7b,
	0x3a, 0x1d, 0x36, 0x58, 0x82, 0x5a, 0x09, 0x17,
	0xe1, 0x69, 0x3e, 0x83, 0xa5, 0x71, 0x5d, 0x09
]);

export const cipher = new Uint8Array([
	0x11, 0xa9, 0x4e, 0xb7, 0x18, 0x53, 0x7e, 0x94,
	0x7d, 0x0f, 0xf3, 0x0c, 0xdd, 0xae, 0x16, 0xae,
	0xab, 0x42, 0x9e, 0xac, 0x09, 0x2b, 0x22, 0x00,
	0x06, 0xb1, 0x9c, 0xcc, 0xb5, 0x26, 0xb4, 0x30,
	0xeb, 0x76, 0x83, 0xc0, 0xdf, 0x90, 0x3a, 0x88,
	0xf6, 0xf1, 0x09, 0x52, 0xbc, 0xa4, 0xd6, 0x45,
	0x28, 0x4f, 0xf7, 0xed, 0x95, 0xc6, 0xa4, 0xe9,
	0x67, 0xf5, 0xe7, 0xae, 0x22, 0xc9, 0x33, 0xcb
]);

export const mGHash = new Uint8Array([
	0x1c, 0x09, 0xf4, 0x62, 0xf1, 0xb5, 0x8f, 0xc1,
	0x40, 0xc9, 0x3c, 0xda, 0x6f, 0xec, 0x88, 0x85,
	0x08, 0x44, 0xe3, 0xf0, 0x04, 0xb7, 0x24, 0x87,
	0xb6, 0x53, 0x39, 0xbd, 0xc0, 0xe4, 0x17, 0x97
]);

export const index_counts = [1000, 1000, 1000];
export const ciphers_count = 3000;
export const elements_count = 1000 * 1000 * 1000;
export const idx = 12345678;
export const rows = [ Math.floor(idx / (1000 * 1000)), Math.floor((idx % (1000 * 1000)) / 1000), (idx % 1000) ];
export const selectorHash = new Uint8Array([
	0xda, 0x20, 0x9d, 0x4f, 0x85, 0xad, 0x0d, 0xb2,
	0x68, 0x45, 0x6f, 0x0d, 0x4e, 0x9e, 0x90, 0x7f,
	0x8f, 0x87, 0x31, 0xa6, 0x69, 0x5d, 0xa5, 0x5f,
	0x1f, 0x3d, 0x19, 0x2f, 0x59, 0xac, 0xe9, 0x0c
]);

export const runTests = (createEpir: EpirCreateFunction, createDecryptionContext: DecryptionContextCreateFunction) => {
	
	let epir: EpirBase;
	let decCtx: DecryptionContextBase;
	
	beforeAll(async () => {
		epir = await createEpir();
		decCtx = await createDecryptionContext(MG_DEFAULT_PATH);
	});
	
	describe('ECElGamal', () => {
		test('create private key', () => {
			const privkey = epir.createPrivkey();
			expect(privkey.byteLength).toBe(SCALAR_SIZE);
		});
		
		test('create public key', () => {
			const pubkeyTest = epir.createPubkey(privkey.buffer);
			expect(new Uint8Array(pubkeyTest)).toEqual(pubkey);
		});
		
		test('encrypt (normal)', () => {
			const cipherTest = epir.encrypt(pubkey.buffer, msg, r.buffer);
			expect(new Uint8Array(cipherTest)).toEqual(cipher);
		});
		
		test('encrypt (fast)', () => {
			const cipherTest = epir.encryptFast(privkey.buffer, msg, r.buffer);
			expect(new Uint8Array(cipherTest)).toEqual(cipher);
		});
		
		test('create DecryptionContext from ArrayBuffer', async () => {
			const decCtx2 = await createDecryptionContext(decCtx.getMG());
			const mG = decCtx2.getMG();
			expect(sha256sum(mG)).toEqual(mGHash);
		});
		
		//test('interpolation search of mG', async () => {
		//});
		
		test('decrypt (success)', () => {
			expect(decCtx.decryptCipher(privkey.buffer, cipher.buffer)).toBe(msg);
		});
		
		test('decrypt (fail)', () => {
			expect(() => decCtx.decryptCipher(pubkey.buffer, cipher.buffer)).toThrow(/^Failed to decrypt\.$/);
		});
		
		test('random encrypt (normal)', () => {
			const cipherTest = epir.encrypt(pubkey.buffer, msg);
			expect(decCtx.decryptCipher(privkey.buffer, cipherTest)).toBe(msg);
		});
		
		test('random encrypt (fast)', () => {
			const cipherTest = epir.encryptFast(privkey.buffer, msg);
			expect(decCtx.decryptCipher(privkey.buffer, cipherTest)).toBe(msg);
		});
	});
	
	describe('Selector', () => {
		test('ciphers count', () => {
			expect(epir.ciphersCount(index_counts)).toBe(ciphers_count);
		});
		
		test('elements count', () => {
			expect(epir.elementsCount(index_counts)).toBe(elements_count);
		});
		
		//test('create choice', async () => {
		//});
		
		test('create selector (deterministic, normal)', async () => {
			const selector = await epir.createSelector(pubkey.buffer, index_counts, idx, generateRandomScalars(ciphers_count));
			expect(sha256sum(selector)).toEqual(selectorHash);
		});
		
		test('create selector (deterministic, fast)', async () => {
			const selector = await epir.createSelectorFast(privkey.buffer, index_counts, idx, generateRandomScalars(ciphers_count));
			expect(sha256sum(selector)).toEqual(selectorHash);
		});
		
		test('create selector (random, normal)', async () => {
			const selector = await epir.createSelector(pubkey.buffer, index_counts, idx);
			expect(selector.byteLength).toBe(ciphers_count * CIPHER_SIZE);
		});
		
		test('create selector (random, fast)', async () => {
			const selector = await epir.createSelectorFast(privkey.buffer, index_counts, idx);
			expect(selector.byteLength).toBe(ciphers_count * CIPHER_SIZE);
		});
	});
};

if(require.main === null) {
	runTests(createEpir, createDecryptionContext);
}

