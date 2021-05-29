/**
 * Node.js (TypeScript) bindings for Native C EllipticPIR library interface.
 */

import {
	EpirBase,
	EpirCreateFunction,
	DecryptionContextBase,
	DecryptionContextParameter,
	DecryptionContextCreateFunction,
	SelectorFactoryBase,
	DEFAULT_CAPACITIES,
	DEFAULT_MMAX
} from './EpirBase';

const epir_napi = require('bindings')('epir');

export interface DecryptionContextNapi {
	constructor(path: string): DecryptionContextNapi;
	getMG(): ArrayBuffer;
	decrypt(privkey: ArrayBuffer, cipher: ArrayBuffer): number;
	replyDecrypt(privkey: ArrayBuffer, dimension: number, packing: number, reply: ArrayBuffer): Promise<ArrayBuffer>;
}

export class DecryptionContext implements DecryptionContextBase {
	
	constructor(public napi: DecryptionContextNapi) {
	}
	
	getMG(): ArrayBuffer {
		return this.napi.getMG();
	}
	
	decryptCipher(privkey: ArrayBuffer, cipher: ArrayBuffer): number {
		return this.napi.decrypt(privkey, cipher);
	}
	
	decryptReply(privkey: ArrayBuffer, dimension: number, packing: number, reply: ArrayBuffer): Promise<ArrayBuffer> {
		return this.napi.replyDecrypt(privkey, dimension, packing, reply);
	}
	
}

export const createDecryptionContext: DecryptionContextCreateFunction = async (
	param?: DecryptionContextParameter, mmax: number = DEFAULT_MMAX) => {
	const napi = await new Promise<DecryptionContextNapi>((resolve) => {
		if((typeof param === 'undefined') || (typeof param === 'string') || (param instanceof ArrayBuffer)) {
			resolve(new epir_napi.DecryptionContext(param, mmax));
		} else {
			// We ensure that all the JS callbacks are called.
			const napi = new epir_napi.DecryptionContext({ cb: (points_computed: number) => {
				param.cb(points_computed);
				if(points_computed == mmax) {
					resolve(napi);
				}
			}, interval: param.interval }, mmax);
		}
	});
	return new DecryptionContext(napi);
};

export interface SelectorFactoryNapi {
	constructor(isFast: boolean, key: ArrayBuffer, capacityZero: number, capacityOne: number): SelectorFactoryNapi;
	fill: () => Promise<void>;
	create: (indexCounts: number[], idx: number) => ArrayBuffer;
}

export class SelectorFactory extends SelectorFactoryBase {
	
	napi: SelectorFactoryNapi;
	
	constructor(
		public readonly isFast: boolean, public readonly key: ArrayBuffer,
		public readonly capacities: number[] = DEFAULT_CAPACITIES) {
		super(isFast, key, capacities);
		this.napi = new epir_napi.SelectorFactory(isFast, key, capacities[0], capacities[1]);
	}
	
	fill(): Promise<void> {
		return this.napi.fill();
	}
	
	create(indexCounts: number[], idx: number, refill = true): ArrayBuffer {
		const selector = this.napi.create(indexCounts, idx);
		if(refill) this.fill();
		return selector;
	}
	
}

export class Epir implements EpirBase {
	
	createPrivkey(): ArrayBuffer {
		return epir_napi.create_privkey();
	}
	
	createPubkey(privkey: ArrayBuffer): ArrayBuffer {
		return epir_napi.pubkey_from_privkey(privkey);
	}
	
	encrypt(pubkey: ArrayBuffer, msg: number, r?: ArrayBuffer): ArrayBuffer {
		return r ? epir_napi.encrypt(pubkey, msg, r) : epir_napi.encrypt(pubkey, msg);
	}
	
	encryptFast(privkey: ArrayBuffer, msg: number, r?: ArrayBuffer): ArrayBuffer {
		return r ? epir_napi.encrypt_fast(privkey, msg, r) : epir_napi.encrypt_fast(privkey, msg);
	}
	
	ciphersCount(index_counts: number[]): number {
		return epir_napi.ciphers_count(index_counts);
	}
	
	elementsCount(index_counts: number[]): number {
		return epir_napi.elements_count(index_counts);
	}
	
	createSelector(pubkey: ArrayBuffer, index_counts: number[], idx: number, r?: ArrayBuffer): Promise<ArrayBuffer> {
		return epir_napi.selector_create(pubkey, index_counts, idx, r);
	}
	
	createSelectorFast(privkey: ArrayBuffer, index_counts: number[], idx: number, r?: ArrayBuffer): Promise<ArrayBuffer> {
		return epir_napi.selector_create_fast(privkey, index_counts, idx, r);
	}
	
	// For testing.
	computeReplySize(dimension: number, packing: number, elem_size: number): number {
		return epir_napi.reply_size(dimension, packing, elem_size);
	}
	
	computeReplyRCount(dimension: number, packing: number, elem_size: number): number {
		return epir_napi.reply_r_count(dimension, packing, elem_size);
	}
	
	computeReplyMock(pubkey: ArrayBuffer, dimension: number, packing: number, elem: ArrayBuffer, r?: ArrayBuffer): ArrayBuffer {
		return (r ?
			epir_napi.reply_mock(pubkey, dimension, packing, elem, r) :
			epir_napi.reply_mock(pubkey, dimension, packing, elem));
	}
	
}

export const createEpir: EpirCreateFunction = async () => {
	return new Epir();
};

