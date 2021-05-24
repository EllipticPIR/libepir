
export const SCALAR_SIZE = 32;
export const POINT_SIZE = 32;
export const CIPHER_SIZE = 2 * POINT_SIZE;

export const DEFAULT_MMAX_MOD = 24;
export const DEFAULT_MMAX = 1 << DEFAULT_MMAX_MOD;

export type DecryptionContextCallbackFunction = ((points_computed: number) => void);
export type DecryptionContextCallback = { cb: DecryptionContextCallbackFunction, interval: number };
export type DecryptionContextParameter = string | ArrayBuffer | DecryptionContextCallback;

export type DecryptionContextCreateFunction =
	(param?: DecryptionContextParameter, mmax?: number) => Promise<DecryptionContextBase>;

export interface DecryptionContextBase {
	getMG(): ArrayBuffer;
	decryptCipher(privkey: ArrayBuffer, cipher: ArrayBuffer): number;
	decryptReply(privkey: ArrayBuffer, dimension: number, packing: number, reply: ArrayBuffer): Promise<ArrayBuffer>;
}

export type EpirCreateFunction = () => Promise<EpirBase>;

export interface EpirBase {
	createPrivkey(): ArrayBuffer;
	createPubkey(privkey: ArrayBuffer): ArrayBuffer;
	encrypt(pubkey: ArrayBuffer, msg: number, r?: ArrayBuffer): ArrayBuffer;
	encryptFast(privkey: ArrayBuffer, msg: number, r?: ArrayBuffer): ArrayBuffer;
	ciphersCount(index_counts: number[]): number;
	elementsCount(index_counts: number[]): number;
	createSelector(pubkey: ArrayBuffer, index_counts: number[], idx: number, r?: ArrayBuffer): Promise<ArrayBuffer>;
	createSelectorFast(privkey: ArrayBuffer, index_counts: number[], idx: number, r?: ArrayBuffer): Promise<ArrayBuffer>;
	// For testing.
	computeReplySize(dimension: number, packing: number, elem_size: number): number;
	computeReplyRCount(dimension: number, packing: number, elem_size: number): number;
	computeReplyMock(pubkey: ArrayBuffer, dimension: number, packing: number, elem: ArrayBuffer, r?: ArrayBuffer): ArrayBuffer;
}

