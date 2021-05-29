
import crypto from 'crypto';

import { SCALAR_SIZE } from '../types';
import {
	time, arrayBufferConcat, arrayBufferCompare, arrayBufferToHex, hexToArrayBuffer, checkIsHex,
	getRandomBytes, isCanonical, getRandomScalar, getRandomScalars, getRandomScalarsConcat
} from '../util';

let getRandomValues: ((buf: Uint8Array) => void) = (buf: Uint8Array) => {
	for(let i=0; i<buf.length; i++) {
		buf[i] = 0;
	}
};

test('time', () => {
	expect(time()).toBeLessThanOrEqual(Date.now());
});

describe('ArrayBuffer', () => {
	test('arrayBufferConcat', () => {
		const concat = arrayBufferConcat([new Uint8Array([0]).buffer, new Uint8Array([1]).buffer]);
		expect(new Uint8Array(concat)).toEqual(new Uint8Array([0, 1]));
	});
	test('arrayBufferCompare', () => {
		const a = new Uint8Array([0, 1, 2, 3]).buffer;
		const b = new Uint8Array([1, 2, 3, 4]).buffer;
		expect(arrayBufferCompare(a, 1, b, 0, 3)).toBe(0);
		expect(arrayBufferCompare(a, 0, b, 0, 4)).toBeLessThan(0);
		expect(arrayBufferCompare(b, 0, a, 0, 4)).toBeGreaterThan(0);
	});
	test('arrayBufferToHex', () => {
		const a = new Uint8Array([0x00, 0x01, 0xfe, 0xff]).buffer;
		expect(arrayBufferToHex(a)).toBe('0001feff');
	});
	test('hexToArrayBuffer (null)', () => {
		expect(new Uint8Array(hexToArrayBuffer(''))).toEqual(new Uint8Array([]));
	});
	test('hexToArrayBuffer (0x0001feff)', () => {
		expect(new Uint8Array(hexToArrayBuffer('0001feff'))).toEqual(new Uint8Array([0x00, 0x01, 0xfe, 0xff]));
	});
	test('checkIsHex', () => {
		expect(checkIsHex('0123456789abcdefABCDEF')).toBe(true);
		expect(checkIsHex('0123456789abcdefABCDEF', 11)).toBe(true);
		expect(checkIsHex('0123456789abcdefABCDEF', 12)).toBe(false);
		expect(checkIsHex('x')).toBe(false);
	});
});

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

describe('isCanonical', () => {
	test('true', () => {
		expect(isCanonical(zero)).toBe(true);
	});
	test('false', () => {
		expect(isCanonical(notCanonical)).toBe(false);
	});
});

describe('Random', () => {
	test('getRandomBytes', () => {
		expect(getRandomBytes(256).byteLength).toBe(256);
	});
	test('getRandomScalar', async () => {
		expect(getRandomScalar().byteLength).toBe(SCALAR_SIZE);
	});
	test('getRandomScalar (fail for first)', async () => {
		let i = 0;
		const randoms: Uint8Array[] = [zero, one];
		getRandomValues = global.self.crypto.getRandomValues;
		Object.defineProperty(global.self.crypto, 'getRandomValues', {
			value: (buf: Uint8Array) => buf.set(randoms[i++]),
		});
		expect(new Uint8Array(getRandomScalar())).toEqual(one);
		Object.defineProperty(global.self.crypto, 'getRandomValues', {
			value: getRandomValues,
		});
	});
	test('getRandomScalars', async () => {
		getRandomValues = (buf: Uint8Array) => buf.set(crypto.randomBytes(buf.length));
		expect(getRandomScalars(256)).toHaveLength(256);
	});
	test('getRandomScalarsConcat', async () => {
		getRandomValues = (buf: Uint8Array) => buf.set(crypto.randomBytes(buf.length));
		expect(getRandomScalarsConcat(256).byteLength).toBe(256 * SCALAR_SIZE);
	});
});

