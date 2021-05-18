
import crypto from 'crypto';

import { EpirBase, DecryptionContextBase, DecryptionContextParameter } from './EpirBase';

const MMAX = 1 << 16;

let x: number;
let y: number;
let z: number;
let w: number;

const xorshift_init = () => {
	x = 123456789;
	y = 362436069;
	z = 521288629;
	w = 88675123;
};

const shiftL = (n: number, cnt: number) => {
	return (n * (2 ** cnt)) & 0xffffffff;
};

const xorshift = () => {
	const t = x ^ (shiftL(x, 11));
	x = y; y = z; z = w;
	w = (w ^ (w >>> 19)) ^ (t ^ (t >>> 8));
	return w;
};

const sha256sum = (buf: Uint8Array): Uint8Array => {
	const hash = crypto.createHash('sha256');
	hash.update(buf);
	return new Uint8Array(Buffer.from(hash.digest('hex'), 'hex'));
};

const privkey = new Uint8Array([
	0x7e, 0xf6, 0xad, 0xd2, 0xbe, 0xd5, 0x9a, 0x79,
	0xba, 0x6e, 0xdc, 0xfb, 0xa4, 0x8f, 0xde, 0x7a,
	0x55, 0x31, 0x75, 0x4a, 0xf5, 0x93, 0x76, 0x34,
	0x6c, 0x8b, 0x52, 0x84, 0xee, 0xf2, 0x52, 0x07
]);

const pubkey = new Uint8Array([
	0x9c, 0x76, 0x82, 0x3d, 0xbd, 0xb9, 0xbf, 0x04,
	0x8f, 0xc5, 0xc2, 0xaf, 0x00, 0x0e, 0x28, 0xa1,
	0x48, 0xee, 0x02, 0x19, 0x99, 0xfb, 0x7f, 0x21,
	0xca, 0x1f, 0x84, 0xb8, 0xfe, 0x73, 0xd7, 0xe8
]);

const msg = 0x12345678 & ((1 << 24) - 1);

const r = new Uint8Array([
	0x42, 0xff, 0x2d, 0x98, 0x4a, 0xe5, 0xa2, 0x8f,
	0x7d, 0x02, 0x69, 0x87, 0xc7, 0x10, 0x9a, 0x7b,
	0x3a, 0x1d, 0x36, 0x58, 0x82, 0x5a, 0x09, 0x17,
	0xe1, 0x69, 0x3e, 0x83, 0xa5, 0x71, 0x5d, 0x09
]);

const cipher = new Uint8Array([
	0x11, 0xa9, 0x4e, 0xb7, 0x18, 0x53, 0x7e, 0x94,
	0x7d, 0x0f, 0xf3, 0x0c, 0xdd, 0xae, 0x16, 0xae,
	0xab, 0x42, 0x9e, 0xac, 0x09, 0x2b, 0x22, 0x00,
	0x06, 0xb1, 0x9c, 0xcc, 0xb5, 0x26, 0xb4, 0x30,
	0xeb, 0x76, 0x83, 0xc0, 0xdf, 0x90, 0x3a, 0x88,
	0xf6, 0xf1, 0x09, 0x52, 0xbc, 0xa4, 0xd6, 0x45,
	0x28, 0x4f, 0xf7, 0xed, 0x95, 0xc6, 0xa4, 0xe9,
	0x67, 0xf5, 0xe7, 0xae, 0x22, 0xc9, 0x33, 0xcb
]);

const mGHash = new Uint8Array([
	0x1c, 0x09, 0xf4, 0x62, 0xf1, 0xb5, 0x8f, 0xc1,
	0x40, 0xc9, 0x3c, 0xda, 0x6f, 0xec, 0x88, 0x85,
	0x08, 0x44, 0xe3, 0xf0, 0x04, 0xb7, 0x24, 0x87,
	0xb6, 0x53, 0x39, 0xbd, 0xc0, 0xe4, 0x17, 0x97
]);

const mGHashSmall = new Uint8Array([
	0x8c, 0x55, 0x49, 0x7e, 0x28, 0xd5, 0xea, 0x75,
	0x15, 0xdd, 0x32, 0xb3, 0x98, 0x34, 0x0b, 0xfa,
	0xf8, 0x89, 0x40, 0x35, 0xe0, 0x30, 0xd2, 0x13,
	0x50, 0x80, 0x84, 0x31, 0xb8, 0x00, 0x8a, 0xf2
]);

const index_counts = [1000, 1000, 1000];
const ciphers_count = 3000;
const elements_count = 1000 * 1000 * 1000;
const idx = 12345678;
const rows = [ Math.floor(idx / (1000 * 1000)), Math.floor((idx % (1000 * 1000)) / 1000), (idx % 1000) ];
const selectorHash = new Uint8Array([
	0xda, 0x20, 0x9d, 0x4f, 0x85, 0xad, 0x0d, 0xb2,
	0x68, 0x45, 0x6f, 0x0d, 0x4e, 0x9e, 0x90, 0x7f,
	0x8f, 0x87, 0x31, 0xa6, 0x69, 0x5d, 0xa5, 0x5f,
	0x1f, 0x3d, 0x19, 0x2f, 0x59, 0xac, 0xe9, 0x0c
]);

export const runTests = (
	Epir: new () => EpirBase,
	DecryptionContext: new (param?: DecryptionContextParameter, mmax?: number) => DecryptionContextBase) => {
	
	// For WebAssembly tests, we have tests which uses max CPU cores (x2 for main threads and worker threads).
	const testsWithWorkersCount = 7;
	process.setMaxListeners(testsWithWorkersCount * 2 * navigator.hardwareConcurrency);
	
	let epir: EpirBase;
	let decCtx: DecryptionContextBase;
	
	const generateRandomScalars = (cnt: number) => {
		const r = new Uint8Array(cnt * 32);
		xorshift_init();
		for(let i=0; i<cnt; i++) {
			for(let j=0; j<32; j++) {
				r[i * 32 + j] = xorshift() & 0xff;
			}
			r[i * 32 + 32 - 1] &= 0x1f;
		}
		return r;
	};
	
	beforeAll(async () => {
		epir = new Epir();
		await epir.init();
		decCtx = new DecryptionContext(`${process.env['HOME']}/.EllipticPIR/mG.bin`);
		await decCtx.init();
	});
	
	describe('ECElGamal', () => {
		test('create private key', async () => {
			const privkey = epir.createPrivkey();
			expect(privkey).toHaveLength(32);
		});
		
		test('create public key', async () => {
			const pubkeyTest = epir.createPubkey(privkey);
			expect(new Uint8Array(pubkeyTest)).toEqual(pubkey);
		});
		
		test('encrypt (normal)', async () => {
			const cipherTest = epir.encrypt(pubkey, msg, r);
			expect(new Uint8Array(cipherTest)).toEqual(cipher);
		});
		
		test('encrypt (fast)', async () => {
			const cipherTest = epir.encryptFast(privkey, msg, r);
			expect(new Uint8Array(cipherTest)).toEqual(cipher);
		});
		
		test('generate mG (without callback)', async () => {
			const decCtx = new DecryptionContext(undefined, MMAX);
			await decCtx.init();
			const mG = decCtx.getMG();
			expect(sha256sum(mG)).toEqual(mGHashSmall);
		});
		
		test('generate mG (with callback)', async () => {
			let pointsComputed = 0;
			const decCtx = new DecryptionContext((pointsComputedTest: number) => {
				pointsComputed++;
				expect(pointsComputedTest).toBe(pointsComputed);
			}, MMAX);
			await decCtx.init();
			const mG = decCtx.getMG();
			expect(sha256sum(mG)).toEqual(mGHashSmall);
		});
		
		//test('interpolation search of mG', async () => {
		//});
		
		test('decrypt (success)', async () => {
			expect(decCtx.decryptCipher(privkey, cipher)).toBe(msg);
		});
		
		test('decrypt (fail)', async () => {
			expect(() => decCtx.decryptCipher(pubkey, cipher)).toThrow(/^Failed to decrypt\.$/);
		});
		
		test('random encrypt (normal)', async () => {
			const cipherTest = epir.encrypt(pubkey, msg);
			expect(decCtx.decryptCipher(privkey, cipherTest)).toBe(msg);
		});
		
		test('random encrypt (fast)', async () => {
			const cipherTest = epir.encryptFast(privkey, msg);
			expect(decCtx.decryptCipher(privkey, cipherTest)).toBe(msg);
		});
	});
	
	describe('Selector', () => {
		test('ciphers count', async () => {
			expect(epir.ciphersCount(index_counts)).toBe(ciphers_count);
		});
		
		test('elements count', async () => {
			expect(epir.elementsCount(index_counts)).toBe(elements_count);
		});
		
		//test('create choice', async () => {
		//});
		
		test('create selector (deterministic, normal)', async () => {
			const selector = await epir.createSelector(pubkey, index_counts, idx, generateRandomScalars(ciphers_count));
			expect(sha256sum(selector)).toEqual(selectorHash);
		});
		
		test('create selector (deterministic, fast)', async () => {
			const selector = await epir.createSelectorFast(privkey, index_counts, idx, generateRandomScalars(ciphers_count));
			expect(sha256sum(selector)).toEqual(selectorHash);
		});
		
		test('create selector (random, normal)', async () => {
			const selector = await epir.createSelector(pubkey, index_counts, idx);
			expect(selector).toHaveLength(ciphers_count * 64);
		});
		
		test('create selector (random, fast)', async () => {
			const selector = await epir.createSelectorFast(privkey, index_counts, idx);
			expect(selector).toHaveLength(ciphers_count * 64);
		});
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
			return elem;
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
			const reply = epir.computeReplyMock(pubkey, DIMENSION, PACKING, elem, generateRandomScalars(reply_r_count));
			const decrypted = await decCtx.decryptReply(privkey, DIMENSION, PACKING, reply);
			expect(new Uint8Array(decrypted.subarray(0, ELEM_SIZE))).toEqual(elem);
		});
		
		test('decrypt a reply (random, success)', async () => {
			const elem = generateElem();
			const reply = epir.computeReplyMock(pubkey, DIMENSION, PACKING, elem);
			const decrypted = await decCtx.decryptReply(privkey, DIMENSION, PACKING, reply);
			expect(new Uint8Array(decrypted.subarray(0, ELEM_SIZE))).toEqual(elem);
		});
		
		test('decrypt a reply (random, fail)', async () => {
			const elem = generateElem();
			const reply = epir.computeReplyMock(pubkey, DIMENSION, PACKING, elem);
			await expect(decCtx.decryptReply(pubkey, DIMENSION, PACKING, reply)).rejects.toThrow(/^Failed to decrypt\.$/);
		});
	});
	
};

