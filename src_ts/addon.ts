/**
 * Node.js (TypeScript) bindings for Native C EllipticPIR library interface.
 */

import epir_t from './epir_t';

const epir_napi = require('../build/Release/epir');

export interface DecryptionContext {
	constructor(path: string): DecryptionContext;
	replyDecrypt: (reply: Uint8Array, privkey: Uint8Array, dimension: number, packing: number) => Uint8Array;
}

export const createEpir = async (): Promise<epir_t<DecryptionContext>> => {
	
	const create_privkey = (): Uint8Array => {
		return epir_napi.create_privkey();
	};
	
	const pubkey_from_privkey = (pubkey: Uint8Array): Uint8Array => {
		return epir_napi.pubkey_from_privkey(pubkey);
	};
	
	const get_decryption_context = async (param?: string | Uint8Array | ((p: number) => void)): Promise<DecryptionContext> => {
		if(param === undefined || typeof param == 'function') {
			// XXX:
			throw new Error('Generating mG.bin is not supported.');
		} else if(typeof param == 'string') {
			return new epir_napi.DecryptionContext(param);
		} else {
			// XXX:
			throw new Error('Loading from Uint8Array is not supported.');
		}
	};
	
	const selector_create = async (
		pubkey: Uint8Array, index_counts: number[], idx: number): Promise<Uint8Array> => {
		return new Promise((resolve, reject) => {
			resolve(epir_napi.selector_create(pubkey, index_counts, idx));
		});
	};
	
	const selector_create_fast = async (
		privkey: Uint8Array, index_counts: number[], idx: number): Promise<Uint8Array> => {
		return new Promise((resolve, reject) => {
			resolve(epir_napi.selector_create_fast(privkey, index_counts, idx));
		});
	};
	
	const reply_decrypt = async (
		decCtx: DecryptionContext, reply: Uint8Array, privkey: Uint8Array, dimension: number, packing: number):
		Promise<Uint8Array> => {
		return new Promise((resolve, reject) => {
			resolve(decCtx.replyDecrypt(reply, privkey, dimension, packing));
		});
	};
	
	return {
		create_privkey,
		pubkey_from_privkey,
		get_decryption_context,
		selector_create,
		selector_create_fast,
		reply_decrypt,
	};
	
};

export default createEpir;

