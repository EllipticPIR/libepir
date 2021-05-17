
import crypto from 'crypto';

import { epir_t } from './epir_t';

const MMAX = 1 << 16;

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

const index_counts = [1000, 1000, 1000];
const ciphers_count = 3000;
const idx = 12345678;
const rows = [ Math.floor(idx / (1000 * 1000)), Math.floor((idx % (1000 * 1000)) / 1000), (idx % 1000) ];
const selectorHash = new Uint8Array([
	0x7e, 0x3e, 0xc1, 0xa4, 0x30, 0x0b, 0x25, 0x3c,
	0x98, 0x6f, 0x3d, 0xd1, 0x25, 0xd8, 0x4e, 0xad,
	0x43, 0x5c, 0xfe, 0x84, 0x5c, 0x3c, 0x42, 0xb5,
	0x6c, 0x7d, 0xb6, 0x14, 0x4d, 0x6e, 0x22, 0x4f
]);

export const runTests = (createEpir: (() => Promise<epir_t<any>>)) => {
	
	// For WebAssembly tests, we have tests which uses max CPU cores (x2 for main threads and worker threads).
	const testsWithWorkersCount = 4;
	process.setMaxListeners(testsWithWorkersCount * 2 * navigator.hardwareConcurrency);
	
	test('create private key', async () => {
		const epir = await createEpir();
		const privkey = epir.create_privkey();
		expect(privkey).toHaveLength(32);
	});
	
	test('create public key', async () => {
		const epir = await createEpir();
		const pubkeyTest = epir.pubkey_from_privkey(privkey);
		expect(new Uint8Array(pubkeyTest)).toEqual(pubkey);
	});
	
	/*
	test('encrypt (normal)', async () => {
		const epir = await createEpir();
		const cipherTest = epir.encrypt(pubkey, msg, r);
		expect(new Uint8Array(cipherTest)).toEqual(cipher);
	});
	
	test('encrypt (fast)', async () => {
		const epir = await createEpir();
		const cipherTest = epir.encrypt_fast(privkey, msg, r);
		expect(new Uint8Array(cipherTest)).toEqual(cipher);
	});
	*/
	
	test('generate mG', async () => {
		const epir = await createEpir();
		let pointsComputed = 0;
		const decCtx = await epir.get_decryption_context((pointsComputedTest: number) => {
			pointsComputed++;
			expect(pointsComputedTest).toBe(pointsComputed);
		}, MMAX);
		// XXX: check generated data!
	});
	
	/*
	test('interpolation search of mG', async () => {
	});
	*/
	
	test('load mG', async () => {
		const epir = await createEpir();
		const decCtx = await epir.get_decryption_context(`${process.env['HOME']}/.EllipticPIR/mG.bin`);
	});
	
	/*
	test('decrypt (success)', async () => {
	});
	
	test('decrypt (fail)', async () => {
	});
	
	test('random encrypt (normal)', async () => {
	});
	
	test('random encrypt (fast)', async () => {
	});
	*/
	
	/*
	test('ciphers count', async () => {
	});
	
	test('elements count', async () => {
	});
	
	test('create choice', async () => {
	});
	*/
	
	test('create selector (normal)', async () => {
		const epir = await createEpir();
		const privkey = epir.create_privkey();
		const pubkey = epir.pubkey_from_privkey(privkey);
		const selector = await epir.selector_create(pubkey, index_counts, 1024);
		expect(selector).toHaveLength(3000 * 64);
		// XXX: check generated data!
	});
	
	test('create selector (fast)', async () => {
		const epir = await createEpir();
		const privkey = epir.create_privkey();
		const selector = await epir.selector_create_fast(privkey, index_counts, 1024);
		expect(selector).toHaveLength(3000 * 64);
		// XXX: check generated data!
	});
	
	test('decrypt a reply (success)', async () => {
		// XXX: generate mock data.
		const data = require('./bench_js_reply_data.json');
		const epir = await createEpir();
		const decCtx = await epir.get_decryption_context(`${process.env['HOME']}/.EllipticPIR/mG.bin`);
		const decrypted = await epir.reply_decrypt(
			decCtx, new Uint8Array(data.reply), new Uint8Array(data.privkey), data.dimension, data.packing);
		expect(new Uint8Array(decrypted.subarray(0, data.correct.length))).toEqual(new Uint8Array(data.correct));
	});
	
	/*
	test('decrypt a reply (fail)', async () => {
	});
	*/
	
};

