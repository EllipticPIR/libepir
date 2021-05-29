
declare module '*/libepir' {
	namespace libepir {
		export type LibEpir = {
			HEAPU8: Uint8Array,
			_malloc: (len: number) => number,
			_free: (buf: number) => void,
			addFunction: (func: (...args: unknown[]) => unknown, signature: string) => number,
			removeFunction: (buf: number) => void,
		} & { [func: string]: (...args: unknown[]) => unknown; };
		export type LibEpirModule = (() => Promise<LibEpir>);
	}
	const libepir: libepir.LibEpirModule;
	export default libepir;
}

