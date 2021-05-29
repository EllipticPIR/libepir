
export type LibEpir = {
	HEAPU8: Uint8Array,
	_malloc: (len: number) => number,
	_free: (buf: number) => void,
	addFunction: (func: (...args: unknown[]) => unknown, signature: string) => number,
	removeFunction: (buf: number) => void,
} & { [func: string]: (...args: unknown[]) => unknown; };
export type LibEpirModule = (() => Promise<LibEpir>);

export const libEpirModule = require('../dist/libepir') as LibEpirModule;

export class LibEpirHelper {
	
	constructor(public libepir: LibEpir) {
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
	
	free = this.libepir._free;
	
	addFunction = this.libepir.addFunction;
	removeFunction = this.libepir.removeFunction;
	
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

