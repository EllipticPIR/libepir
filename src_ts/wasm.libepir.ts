
import libepir from '../dist/libepir';

export class LibEpirHelper {
	
	// Assigned in the constructor: with ES2022 class fields, field initializers run
	// before parameter properties are assigned, so `free = this.libepir._free` would
	// read an undefined `this.libepir`.
	free: libepir.LibEpir['_free'];
	addFunction: libepir.LibEpir['addFunction'];
	removeFunction: libepir.LibEpir['removeFunction'];
	
	constructor(public libepir: libepir.LibEpir) {
		this.free = libepir._free;
		this.addFunction = libepir.addFunction;
		this.removeFunction = libepir.removeFunction;
	}
	
	store(offset: number, n: number, len: number): void {
		for(let i=0; i<len; i++) {
			this.libepir.HEAPU8[offset + i] = n & 0xff;
			n >>= 8;
		}
	}
	
	store32(offset: number, n: number): void {
		this.store(offset, n, 4);
	}
	
	store64(offset: number, n: number): void {
		this.store(offset, n, 8);
	}
	
	set(buf: ArrayBuffer, offset: number, len: number, buf_: number): void {
		this.libepir.HEAPU8.set(new Uint8Array(buf, offset, len), buf_);
	}
	
	malloc(param: ArrayBuffer | number): number {
		if(typeof param == 'number') {
			return this.libepir._malloc(param);
		} else {
			const buf_ = this.libepir._malloc(param.byteLength);
			this.set(param, 0, param.byteLength, buf_);
			return buf_;
		}
	}
	
	call(func: string, ...params: (ArrayBuffer | number | null)[]): unknown {
		const bufs: number[] = [];
		params = params.map((param) => {
			if(typeof param === 'number' || param === null) {
				return param;
			} else {
				const buf_ = this.malloc(param);
				bufs.push(buf_);
				return buf_;
			}
		});
		const ret = this.libepir[`_epir_${func}`].apply(null, params);
		bufs.forEach((buf_) => this.free(buf_));
		return ret;
	}
	
	slice(begin: number, len: number): ArrayBuffer {
		return this.libepir.HEAPU8.slice(begin, begin + len).buffer;
	}
	
	subarray(begin: number, len: number): Uint8Array {
		return this.libepir.HEAPU8.subarray(begin, begin + len);
	}
	
}

export const createLibEpirHelper = async (): Promise<LibEpirHelper> => {
	return new LibEpirHelper(await libepir());
};

