/**
 * Node.js (TypeScript) bindings for Native C EllipticPIR library interface.
 */

import { EpirBase, DecryptionContextBase, DecryptionContextParameter } from './EpirBase';

const epir_napi = require('bindings')('epir');

export interface DecryptionContextNapi {
	constructor(path: string): DecryptionContextNapi;
	decrypt: (privkey: Uint8Array, cipher: Uint8Array) => number;
	replyDecrypt: (reply: Uint8Array, privkey: Uint8Array, dimension: number, packing: number) => Uint8Array;
}

export class DecryptionContext extends DecryptionContextBase {
	
	napi: DecryptionContextNapi | null = null;
	
	constructor(param?: DecryptionContextParameter, mmax: number = 1 << 24) {
		super(param, mmax);
	}
	
	async init(): Promise<void> {
		return new Promise((resolve, reject) => {
			if(typeof this.param === 'function') {
				// We ensure that all the JS callbacks are called.
				this.napi = new epir_napi.DecryptionContext((points_computed: number) => {
					if(typeof this.param === 'function') this.param(points_computed);
					if(points_computed == this.mmax) {
						resolve();
					}
				}, this.mmax);
			} else {
				this.napi = new epir_napi.DecryptionContext(this.param, this.mmax);
				resolve();
			}
		});
	}
	
	getMG(): ArrayBuffer {
		// XXX:
		throw new Error('Not implemented.');
	}
	
	decryptCipher(privkey: Uint8Array, cipher: Uint8Array): number {
		if(!this.napi) throw new Error('Please call init() first.');
		return this.napi.decrypt(privkey, cipher);
	}
	
	async decryptReply(privkey: Uint8Array, dimension: number, packing: number, reply: Uint8Array): Promise<Uint8Array> {
		return new Promise((resolve, reject) => {
			if(!this.napi) throw new Error('Please call init() first.');
			resolve(this.napi.replyDecrypt(reply, privkey, dimension, packing));
		});
	}
	
}

export class Epir implements EpirBase {
	
	async init(): Promise<void> {
	}
	
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

