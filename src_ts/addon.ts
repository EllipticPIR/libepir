/**
 * Node.js (TypeScript) bindings for Native C EllipticPIR library interface.
 */

import { epir_t } from './epir_t';

const epir_napi = require('bindings')('epir');

export interface DecryptionContext {
	constructor(path: string): DecryptionContext;
	decrypt: (privkey: Uint8Array, cipher: Uint8Array) => number;
	replyDecrypt: (reply: Uint8Array, privkey: Uint8Array, dimension: number, packing: number) => Uint8Array;
}

export const createEpir = async (): Promise<epir_t<DecryptionContext>> => {
	
	const create_privkey = (): Uint8Array => {
		return epir_napi.create_privkey();
	};
	
	const pubkey_from_privkey = (pubkey: Uint8Array): Uint8Array => {
		return epir_napi.pubkey_from_privkey(pubkey);
	};
	
	const encrypt = (pubkey: Uint8Array, msg: number, r?: Uint8Array): Uint8Array => {
		return r ? epir_napi.encrypt(pubkey, msg, r) : epir_napi.encrypt(pubkey, msg);
	};
	
	const encrypt_fast = (privkey: Uint8Array, msg: number, r?: Uint8Array): Uint8Array => {
		return r ? epir_napi.encrypt_fast(privkey, msg, r) : epir_napi.encrypt_fast(privkey, msg);
	};
	
	const get_decryption_context = async (
		param?: string | Uint8Array | ((p: number) => void), mmax: number = 1 << 24): Promise<DecryptionContext> => {
		if(typeof param === 'function') {
			// We ensure that all the JS callbacks are called.
			return new Promise((resolve, reject) => {
				const decCtx = new epir_napi.DecryptionContext((points_computed: number) => {
					param(points_computed);
					if(points_computed == mmax) {
						resolve(decCtx);
					}
				}, mmax);
			});
		}
		return new epir_napi.DecryptionContext(param, mmax);
	};
	
	const decrypt = (ctx: DecryptionContext, privkey: Uint8Array, cipher: Uint8Array) => {
		return ctx.decrypt(privkey, cipher);
	};
	
	const ciphers_count = (index_counts: number[]): number => {
		return epir_napi.ciphers_count(index_counts);
	};
	
	const elements_count = (index_counts: number[]): number => {
		return epir_napi.elements_count(index_counts);
	};
	
	const selector_create = async (
		pubkey: Uint8Array, index_counts: number[], idx: number, r?: Uint8Array): Promise<Uint8Array> => {
		return new Promise((resolve, reject) => {
			resolve(r ?
				epir_napi.selector_create(pubkey, index_counts, idx, r) :
				epir_napi.selector_create(pubkey, index_counts, idx));
		});
	};
	
	const selector_create_fast = async (
		privkey: Uint8Array, index_counts: number[], idx: number, r?: Uint8Array): Promise<Uint8Array> => {
		return new Promise((resolve, reject) => {
			resolve(r ?
				epir_napi.selector_create_fast(privkey, index_counts, idx, r) :
				epir_napi.selector_create_fast(privkey, index_counts, idx));
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
		encrypt,
		encrypt_fast,
		get_decryption_context,
		decrypt,
		ciphers_count,
		elements_count,
		selector_create,
		selector_create_fast,
		reply_decrypt,
	};
	
};

