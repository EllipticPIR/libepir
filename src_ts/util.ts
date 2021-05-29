
import { SCALAR_SIZE } from './EpirBase';

export const time = (): number => Date.now();

export const runMeasurement = async <T>(func: () => (Promise<T> | T)): Promise<{ execTime: number, ret: T }> => {
	const begin = time();
	const ret = func();
	if(ret instanceof Promise) {
		const ret2 = await ret;
		const end = time();
		return { execTime: end - begin, ret: ret2 };
	} else {
		const end = time();
		return { execTime: end - begin, ret: ret };
	}
};

export const printMeasurement = async <T>(
	func: () => (Promise<T> | T), prefix: string, postfix = 'ms.'): Promise<T> => {
	const { execTime, ret } = await runMeasurement<T>(func);
	console.log(`\u001b[32m${prefix} ${execTime.toLocaleString()} ${postfix}\u001b[0m`);
	return ret;
}

export const arrayBufferConcat = (arr: ArrayBuffer[]): ArrayBuffer => {
	const len = arr.reduce((acc, v) => acc + v.byteLength, 0);
	const ret = new Uint8Array(len);
	for(let i=0, offset=0; i<arr.length; i++) {
		ret.set(new Uint8Array(arr[i]), offset);
		offset += arr[i].byteLength;
	}
	return ret.buffer;
}

export const arrayBufferCompare = (
	a: ArrayBuffer, aOffset: number, b: ArrayBuffer, bOffset: number, len: number): number => {
	const aa = new Uint8Array(a, aOffset, len);
	const bb = new Uint8Array(b, bOffset, len);
	for(let i=0; i<len; i++) {
		if(aa[i] == bb[i]) continue;
		return aa[i] - bb[i];
	}
	return 0;
}

export const arrayBufferToHex = (buf: ArrayBuffer): string => {
	const arr = new Uint8Array(buf);
	let ret = '';
	for(const n of arr) {
		ret += Number(n).toString(16).padStart(2, '0');
	}
	return ret;
};

export const hexToArrayBuffer = (hex: string): ArrayBuffer => {
	const split = hex.match(/.{2}/g);
	if(!split) return new ArrayBuffer(0);
	return new Uint8Array(split.map((h) => parseInt(h, 16))).buffer;
};

export const checkIsHex = (hex: string, expectedSize = -1): boolean => {
	const pattern = /^[0-9a-fA-F]+$/;
	if(expectedSize >= 0) {
		return ((hex.length === 2 * expectedSize) && (hex.match(pattern) !== null));
	} else {
		return ((hex.length % 2 === 0) && (hex.match(pattern) !== null));
	}
};

export const getRandomBytes = (len: number): ArrayBuffer => {
	const MAX_ENTROPY = 65536;
	const ret = new Uint8Array(len);
	for(let offset=0; offset<len; offset+=MAX_ENTROPY) {
		window.crypto.getRandomValues(ret.subarray(offset, Math.min(len, offset + MAX_ENTROPY)));
	}
	return ret.buffer;
};

export const isCanonical = (buf: ArrayBuffer): boolean => {
	const bufView = new Uint8Array(buf);
	let c = (bufView[31] & 0x7f) ^ 0x7f;
	for(let i=30; i>0; i--) {
		c |= bufView[i] ^ 0xff;
	}
	const d = (0xed - 1 - bufView[0]) >> 8;
	return !((c == 0) && d)
};

export const isZero = (buf: ArrayBuffer): boolean => {
	return new Uint8Array(buf).reduce<boolean>((acc, v) => acc && (v == 0), true);
};

export const getRandomScalar = (): ArrayBuffer => {
	for(;;) {
		const scalar = getRandomBytes(SCALAR_SIZE);
		new Uint8Array(scalar)[31] &= 0x1f;
		if(!isCanonical(scalar) || isZero(scalar)) continue;
		return scalar;
	}
};

export const getRandomScalars = (cnt: number): ArrayBuffer[] => {
	const ret: ArrayBuffer[] = [];
	for(let i=0; i<cnt; i++) ret.push(getRandomScalar());
	return ret;
}

export const getRandomScalarsConcat = (cnt: number): ArrayBuffer => {
	return arrayBufferConcat(getRandomScalars(cnt));
}

