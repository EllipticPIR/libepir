
export type epir_t<DecryptionContext> = {
	create_privkey: () => Uint8Array;
	pubkey_from_privkey: (pubkey: Uint8Array) => Uint8Array;
	encrypt: (pubkey: Uint8Array, msg: number, r?: Uint8Array) => Uint8Array;
	encrypt_fast: (pubkey: Uint8Array, msg: number, r?: Uint8Array) => Uint8Array;
	get_decryption_context: (
		param?: string | Uint8Array | ((points_computed: number) => void), mmax?: number) => Promise<DecryptionContext>;
	decrypt: (ctx: DecryptionContext, privkey: Uint8Array, cipher: Uint8Array) => number;
	ciphers_count: (index_counts: number[]) => number;
	elements_count: (index_counts: number[]) => number;
	selector_create: (pubkey: Uint8Array, index_counts: number[], idx: number, r?: Uint8Array) => Promise<Uint8Array>;
	selector_create_fast: (privkey: Uint8Array, index_counts: number[], idx: number, r?: Uint8Array) => Promise<Uint8Array>;
	reply_decrypt: (ctx: DecryptionContext, reply: Uint8Array, privkey: Uint8Array, dimension: number, packing: number)
		=> Promise<Uint8Array>;
	// For testing.
	reply_size: (dimension: number, packing: number, elem_size: number) => number;
	reply_r_count: (dimension: number, packing: number, elem_size: number) => number;
	reply_mock: (pubkey: Uint8Array, dimension: number, packing: number, elem: Uint8Array, r?: Uint8Array) => Uint8Array;
};

