
namespace crypto_incognito {
	
	/**
	 * Register native bindings.
	 */
	
	const ci_lib = require('../build/Release/ci_lib');
	
	export const create_privkey = (): Uint8Array => {
		return ci_lib.create_privkey();
	};
	
	export const pubkey_from_privkey = (pubkey: Uint8Array): Uint8Array => {
		return ci_lib.pubkey_from_privkey(pubkey);
	};
	
	export const load_mG = async (path: string): Promise<number> => {
		return new Promise((resolve, reject) => {
			resolve(ci_lib.load_mG(path));
		});
	};
	
	export const selectors_create = async (
		pubkey: Uint8Array, index_counts: BigUint64Array, idx: number): Promise<Uint8Array> => {
		return new Promise((resolve, reject) => {
			resolve(ci_lib.selectors_create(pubkey, index_counts, idx));
		});
	};
	
	export const selectors_create_fast = async (
		privkey: Uint8Array, index_counts: BigUint64Array, idx: number): Promise<Uint8Array> => {
		return new Promise((resolve, reject) => {
			resolve(ci_lib.selectors_create_fast(privkey, index_counts, idx));
		});
	};
	
	export const reply_decrypt = async (
		reply: Uint8Array, privkey: Uint8Array, dimension: number, packing: number): Promise<Uint8Array> => {
		return new Promise((resolve, reject) => {
			resolve(ci_lib.reply_decrypt(reply, privkey, dimension, packing));
		});
	};
	
}

export default crypto_incognito;

