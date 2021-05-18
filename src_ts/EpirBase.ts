
export const SCALAR_SIZE = 32;
export const POINT_SIZE = 32;
export const CIPHER_SIZE = 2 * POINT_SIZE;

export type DecryptionContextParameter = string | Uint8Array | ((points_computed: number) => void);

export abstract class DecryptionContextBase {
	readonly param?: DecryptionContextParameter;
	readonly mmax?: number;
	constructor(param?: DecryptionContextParameter, mmax?: number) {
		this.param = param;
		this.mmax = mmax;
	}
	abstract init(): Promise<void>;
	abstract getMG(): ArrayBuffer;
	abstract decryptCipher(privkey: Uint8Array, cipher: Uint8Array): number;
	abstract decryptReply(privkey: Uint8Array, dimension: number, packing: number, reply: Uint8Array): Promise<Uint8Array>;
}

export interface EpirBase {
	init(): Promise<void>;
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

