/**
 * Node.js (TypeScript) bindings for Native C EllipticPIR library interface.
 */

import {
	EpirBase,
	EpirCreateFunction,
	DecryptionContextBase,
	DecryptionContextParameter,
	DecryptionContextCreateFunction,
	DEFAULT_MMAX
} from './EpirBase';

const epir_napi = require('bindings')('epir');

export interface DecryptionContextNapi {
	constructor(path: string): DecryptionContextNapi;
	getMG: () => Uint8Array;
	decrypt: (privkey: Uint8Array, cipher: Uint8Array) => number;
	replyDecrypt: (reply: Uint8Array, privkey: Uint8Array, dimension: number, packing: number) => Uint8Array;
}

export class DecryptionContext implements DecryptionContextBase {
	
	napi: DecryptionContextNapi;
	
	constructor(napi: DecryptionContextNapi) {
		this.napi = napi;
	}
	
	getMG(): Uint8Array {
		return this.napi.getMG();
	}
	
	decryptCipher(privkey: Uint8Array, cipher: Uint8Array): number {
		return this.napi.decrypt(privkey, cipher);
	}
	
	async decryptReply(privkey: Uint8Array, dimension: number, packing: number, reply: Uint8Array): Promise<Uint8Array> {
		return this.napi.replyDecrypt(reply, privkey, dimension, packing);
	}
	
}

export const createDecryptionContext: DecryptionContextCreateFunction = async (
	param?: DecryptionContextParameter, mmax: number = DEFAULT_MMAX) => {
	const napi = await new Promise<DecryptionContextNapi>((resolve, reject) => {
		if(typeof param === 'function') {
			// We ensure that all the JS callbacks are called.
			const napi = new epir_napi.DecryptionContext((points_computed: number) => {
				param(points_computed);
				if(points_computed == mmax) {
					resolve(napi);
				}
			}, mmax);
		} else {
			resolve(new epir_napi.DecryptionContext(param, mmax));
		}
	});
	return new DecryptionContext(napi);
};

export class Epir implements EpirBase {
	
	createPrivkey(): Uint8Array {
		return epir_napi.create_privkey();
	}
	
	createPubkey(privkey: Uint8Array): Uint8Array {
		return epir_napi.pubkey_from_privkey(privkey);
	}
	
	encrypt(pubkey: Uint8Array, msg: number, r?: Uint8Array): Uint8Array {
		return r ? epir_napi.encrypt(pubkey, msg, r) : epir_napi.encrypt(pubkey, msg);
	}
	
	encryptFast(privkey: Uint8Array, msg: number, r?: Uint8Array): Uint8Array {
		return r ? epir_napi.encrypt_fast(privkey, msg, r) : epir_napi.encrypt_fast(privkey, msg);
	}
	
	ciphersCount(index_counts: number[]): number {
		return epir_napi.ciphers_count(index_counts);
	}
	
	elementsCount(index_counts: number[]): number {
		return epir_napi.elements_count(index_counts);
	}
	
	async createSelector(pubkey: Uint8Array, index_counts: number[], idx: number, r?: Uint8Array): Promise<Uint8Array> {
		return (r ?
			epir_napi.selector_create(pubkey, index_counts, idx, r) :
			epir_napi.selector_create(pubkey, index_counts, idx));
	}
	
	async createSelectorFast(privkey: Uint8Array, index_counts: number[], idx: number, r?: Uint8Array): Promise<Uint8Array> {
		return (r ?
			epir_napi.selector_create_fast(privkey, index_counts, idx, r) :
			epir_napi.selector_create_fast(privkey, index_counts, idx));
	}
	
	// For testing.
	computeReplySize(dimension: number, packing: number, elem_size: number): number {
		return epir_napi.reply_size(dimension, packing, elem_size);
	}
	
	computeReplyRCount(dimension: number, packing: number, elem_size: number): number {
		return epir_napi.reply_r_count(dimension, packing, elem_size);
	}
	
	computeReplyMock(pubkey: Uint8Array, dimension: number, packing: number, elem: Uint8Array, r?: Uint8Array): Uint8Array {
		return (r ?
			epir_napi.reply_mock(pubkey, dimension, packing, elem, r) :
			epir_napi.reply_mock(pubkey, dimension, packing, elem));
	}
	
}

export const createEpir: EpirCreateFunction = async () => {
	return new Epir();
};

