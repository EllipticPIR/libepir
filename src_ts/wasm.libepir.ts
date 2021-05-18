
export type LibEpir = {
	HEAPU8: Uint8Array,
	_malloc: (len: number) => number,
	_free: (buf: number) => void,
	addFunction: (func: (...args: any[]) => any, signature: string) => number,
	removeFunction: (buf: number) => void,
} & { [func: string]: (...args: any[]) => any; };
export type LibEpirModule = (() => Promise<LibEpir>);

export const libEpirModule = require('../dist/libepir') as LibEpirModule;

