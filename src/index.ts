
namespace epir {
	
	/**
	 * Register native bindings.
	 */
	
	const epir = require('../build/Release/epir');
	
	export const create_privkey = (): Uint8Array => {
		return epir.create_privkey();
	};
	
	export const pubkey_from_privkey = (pubkey: Uint8Array): Uint8Array => {
		return epir.pubkey_from_privkey(pubkey);
	};
	
	export const load_mG = async (path: string): Promise<number> => {
		return new Promise((resolve, reject) => {
			resolve(epir.load_mG(path));
		});
	};
	
	export const selector_create = async (
		pubkey: Uint8Array, index_counts: BigUint64Array, idx: number): Promise<Uint8Array> => {
		return new Promise((resolve, reject) => {
			resolve(epir.selector_create(pubkey, index_counts, idx));
		});
	};
	
	export const selector_create_fast = async (
		privkey: Uint8Array, index_counts: BigUint64Array, idx: number): Promise<Uint8Array> => {
		return new Promise((resolve, reject) => {
			resolve(epir.selector_create_fast(privkey, index_counts, idx));
		});
	};
	
	export const reply_decrypt = async (
		reply: Uint8Array, privkey: Uint8Array, dimension: number, packing: number): Promise<Uint8Array> => {
		return new Promise((resolve, reject) => {
			resolve(epir.reply_decrypt(reply, privkey, dimension, packing));
		});
	};
	
}

export default epir;

