
const epir = async () => {
	
	const epir_ = require('../build_em/src/epir.js');
	const epir = await epir_();
	
	epir._epir_randombytes_init();
	
	const create_privkey = (): Uint8Array => {
		const privkey_ = epir._malloc(32);
		epir._epir_create_privkey(privkey_);
		const privkey = new Uint8Array(epir.HEAPU8.subarray(privkey_, privkey_ + 32));
		epir._free(privkey_);
		return privkey;
	};
	
	const pubkey_from_privkey = (privkey: Uint8Array): Uint8Array => {
		const privkey_ = epir._malloc(32);
		epir.HEAPU8.set(privkey, privkey_);
		const pubkey_ = epir._malloc(32);
		epir._epir_pubkey_from_privkey(pubkey_, privkey_);
		const pubkey = new Uint8Array(epir.HEAPU8.subarray(pubkey_, pubkey_ + 32));
		epir._free(pubkey_);
		epir._free(privkey_);
		return pubkey;
	};
	
	const load_mG = async (mG: Uint8Array): Promise<{ mG: number, elemsRead: number }> => {
		return new Promise(async (resolve, reject) => {
			const mG_ = epir._malloc(36 * (1 << 24));
			epir.HEAPU8.set(mG, mG_);
			resolve({mG: mG_, elemsRead: mG.length / 36});
		});
	};
	
	const delete_mG = (mG: number) => {
		epir._free(mG);
	}
	
	const store_uint64_t = (offset: number, n: number) => {
		for(let i=0; i<8; i++) {
			epir.HEAPU8[offset + i] = n & 0xff;
			n >>= 8;
		}
	}
	
	type SelectorCreateFunction = (
		selector: number, key: number, index_counts: BigUint64Array, n_index_counts: number,
		idx_low: number, idex_high: number) => void;
	
	const selector_create_ = async (
		key: Uint8Array, index_counts: number[], idx: number, func: SelectorCreateFunction):
		Promise<Uint8Array> => {
		return new Promise((resolve, reject) => {
			const key_ = epir._malloc(32);
			epir.HEAPU8.set(key, key_);
			const ic_ = epir._malloc(8 * index_counts.length);
			for(let i=0; i<index_counts.length; i++) {
				store_uint64_t(ic_ + 8 * i, index_counts[i]);
			}
			const ciphers = epir._epir_selector_ciphers_count(ic_, index_counts.length);
			const selector_ = epir._malloc(64 * ciphers);
			func(selector_, key_, ic_, index_counts.length, idx&0xffffffff, Math.floor(idx / 0xffffffff)&0xffffffff);
			const selector = new Uint8Array(epir.HEAPU8.subarray(selector_, selector_ + 64 * ciphers));
			epir._free(selector_);
			epir._free(key_);
			epir._free(ic_);
			resolve(selector);
		});
	};
	
	const selector_create = (pubkey: Uint8Array, index_counts: number[], idx: number): Promise<Uint8Array> => {
		return selector_create_(pubkey, index_counts, idx, epir._epir_selector_create);
	};
	
	const selector_create_fast = (privkey: Uint8Array, index_counts: number[], idx: number): Promise<Uint8Array> => {
		return selector_create_(privkey, index_counts, idx, epir._epir_selector_create_fast);
	};
	
	const reply_decrypt = async (
		reply: Uint8Array, privkey: Uint8Array, dimension: number, packing: number, mG: number): Promise<Uint8Array> => {
		return new Promise((resolve, reject) => {
			const reply_ = epir._malloc(reply.length);
			epir.HEAPU8.set(reply, reply_);
			const privkey_ = epir._malloc(32);
			epir.HEAPU8.set(privkey, privkey_);
			const bytes = epir._epir_reply_decrypt(reply_, reply.length, privkey_, dimension, packing, mG, 1 << 24);
			if(bytes < 0) {
				reject('Failed to decrypt.');
				return;
			}
			const decrypted = new Uint8Array(epir.HEAPU8.subarray(reply_, reply_ + bytes));
			epir._free(reply_);
			epir._free(privkey_);
			resolve(decrypted);
		});
	};
	
	return {
		create_privkey,
		pubkey_from_privkey,
		load_mG,
		delete_mG,
		selector_create,
		selector_create_fast,
		reply_decrypt,
	};
	
};

export default epir;

