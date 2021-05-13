
export type epir_t<DecryptionContext> = {
	create_privkey: () => Uint8Array;
	pubkey_from_privkey: (pubkey: Uint8Array) => Uint8Array;
	get_mG?: (param?: string | ((p: number) => void)) => Promise<Uint8Array>;
	get_decryption_context: (param?: string | Uint8Array | ((points_computed: number) => void)) => Promise<DecryptionContext>;
	selector_create: (pubkey: Uint8Array, index_counts: number[], idx: number) => Promise<Uint8Array>;
	selector_create_fast: (privkey: Uint8Array, index_counts: number[], idx: number) => Promise<Uint8Array>;
	reply_decrypt: (ctx: DecryptionContext, reply: Uint8Array, privkey: Uint8Array, dimension: number, packing: number)
		=> Promise<Uint8Array>;
};

