
export type LibEpir = {
	HEAPU8: Uint8Array,
	_malloc: (len: number) => number,
	_free: (buf: number) => void,
	addFunction: (func: (...args: any[]) => any) => number,
	removeFunction: (buf: number) => void,
}
export type LibEpirModule = (() => Promise<LibEpir>);

export const libEpirModule = require('../dist/libepir') as LibEpirModule;

