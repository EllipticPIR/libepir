
import crypto from 'crypto';

import { createEpir, isCanonical } from '../wasm'

let getRandomValues = (buf: Uint8Array) => {};

// For WebAssembly tests, we have tests which uses max CPU cores (x2 for main threads and worker threads).
const testsWithWorkersCount = 2;
process.setMaxListeners(testsWithWorkersCount * 2 * navigator.hardwareConcurrency);

Object.defineProperty(global.self, 'crypto', {
	value: {
		getRandomValues: (buf: Uint8Array) => getRandomValues(buf),
	}
});

describe('Browser', () => {
	test('create private key', async () => {
		getRandomValues = (buf: Uint8Array) => buf.set(crypto.randomBytes(buf.length));
		const epir = await createEpir();
		const privkey = epir.createPrivkey();
		expect(privkey).toHaveLength(32);
	});
});

describe('WebAssembly', () => {
	const zero = new Uint8Array([
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	]);
	const one = new Uint8Array([
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	]);
	const notCanonical = new Uint8Array([
		0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
	]);
	test('isCanonical (true)', () => {
		expect(isCanonical(zero)).toBe(true);
	});
	test('isCanonical (false)', () => {
		expect(isCanonical(notCanonical)).toBe(false);
	});
	test('getRandomScalar', async () => {
		const randoms = [zero, one];
		let offset = 0;
		getRandomValues = (buf: Uint8Array) => buf.set(randoms[offset++]);
		const epir = await createEpir();
		const privkey = epir.createPrivkey();
		expect(privkey).toEqual(one);
	});
});

