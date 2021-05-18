
export const SCALAR_SIZE = 32;
export const POINT_SIZE = 32;
export const CIPHER_SIZE = 2 * POINT_SIZE;

export const DEFAULT_MMAX_MOD = 24;
export const DEFAULT_MMAX = 1 << DEFAULT_MMAX_MOD;

export type DecryptionContextParameter = string | Uint8Array | ((points_computed: number) => void);

export type DecryptionContextCreateFunction =
	(param?: DecryptionContextParameter, mmax?: number) => Promise<DecryptionContextBase>;

export interface DecryptionContextBase {
	getMG(): Uint8Array;
	decryptCipher(privkey: Uint8Array, cipher: Uint8Array): number;
	decryptReply(privkey: Uint8Array, dimension: number, packing: number, reply: Uint8Array): Promise<Uint8Array>;
}

export type EpirCreateFunction = () => Promise<EpirBase>;

export interface EpirBase {
	createPrivkey(): Uint8Array;
	createPubkey(privkey: Uint8Array): Uint8Array;
	encrypt(pubkey: Uint8Array, msg: number, r?: Uint8Array): Uint8Array;
	encryptFast(privkey: Uint8Array, msg: number, r?: Uint8Array): Uint8Array;
	ciphersCount(index_counts: number[]): number;
	elementsCount(index_counts: number[]): number;
	createSelector(pubkey: Uint8Array, index_counts: number[], idx: number, r?: Uint8Array): Promise<Uint8Array>;
	createSelectorFast(privkey: Uint8Array, index_counts: number[], idx: number, r?: Uint8Array): Promise<Uint8Array>;
	// For testing.
	computeReplySize(dimension: number, packing: number, elem_size: number): number;
	computeReplyRCount(dimension: number, packing: number, elem_size: number): number;
	computeReplyMock(pubkey: Uint8Array, dimension: number, packing: number, elem: Uint8Array, r?: Uint8Array): Uint8Array;
}

