
export type LibEpir = {
	HEAPU8: Uint8Array,
	_malloc: (len: number) => number,
	_free: (buf: number) => void,
	addFunction: (func: (...args: any[]) => any, signature: string) => number,
	removeFunction: (buf: number) => void,
} & { [func: string]: (...args: any[]) => any; };
export type LibEpirModule = (() => Promise<LibEpir>);

export const libEpirModule = require('../dist/libepir') as LibEpirModule;

export class LibEpirHelper {
	
	constructor(public libepir: LibEpir) {
	}
	
	store(offset: number, n: number, len: number) {
		for(let i=0; i<len; i++) {
			this.libepir.HEAPU8[offset + i] = n & 0xff;
			n >>= 8;
		}
	}
	
	store32(offset: number, n: number) {
		this.store(offset, n, 4);
	}
	
	store64(offset: number, n: number) {
		this.store(offset, n, 8);
	}
	
	set(buf: Uint8Array, offset: number) {
		this.libepir.HEAPU8.set(buf, offset);
	}
	
	malloc(param: Uint8Array | number): number {
		if(typeof param == 'number') {
			return this.libepir._malloc(param);
		} else {
			const buf_ = this.libepir._malloc(param.length);
			this.libepir.HEAPU8.set(param, buf_);
			return buf_;
		}
	}
	
	free = this.libepir._free;
	
	addFunction = this.libepir.addFunction;
	removeFunction = this.libepir.removeFunction;
	
	call(func: string, ...params: any[]) {
		const bufs: number[] = [];
		params = params.map((param) => {
			if(param instanceof Uint8Array) {
				const buf_ = this.malloc(param);
				bufs.push(buf_);
				return buf_;
			} else {
				return param;
			}
		});
		const ret = this.libepir[`_epir_${func}`].apply(null, params);
		bufs.forEach((buf_) => this.free(buf_));
		return ret;
	}
	
	slice(begin: number, len: number) {
		return this.libepir.HEAPU8.slice(begin, begin + len);
	}
	
	subarray(begin: number, len: number) {
		return this.libepir.HEAPU8.subarray(begin, begin + len);
	}
	
}

