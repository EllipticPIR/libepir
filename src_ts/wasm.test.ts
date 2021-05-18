
import { runTests } from './test_common'
import { createEpir, createDecryptionContext, isCanonical } from './wasm';

runTests(createEpir, createDecryptionContext);

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
		Object.defineProperty(global.self, 'crypto', {
			value: {
				getRandomValues: (buf: Uint8Array) => buf.set(randoms[offset++]),
			}
		});
		const epir = await createEpir();
		const privkey = epir.createPrivkey();
		expect(privkey).toEqual(one);
	});
});

