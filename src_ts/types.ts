
export const SCALAR_SIZE = 32;
export const POINT_SIZE = 32;
export const CIPHER_SIZE = 2 * POINT_SIZE;

export const DEFAULT_MMAX_MOD = 24;
export const DEFAULT_MMAX = 1 << DEFAULT_MMAX_MOD;

export const MG_SIZE = 36;
export const GE25519_P3_SIZE = 4 * 40;

export const MG_DEFAULT_PATH = `${process.env['HOME']}/.EllipticPIR/mG.bin`;

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

export const DEFAULT_CAPACITIES = [10000, 100];

export abstract class SelectorFactoryBase {
	constructor(public readonly isFast: boolean, public readonly key: ArrayBuffer, public readonly capacities: number[]) {}
	abstract fill(): Promise<void>;
	abstract create(indexCounts: number[], idx: number, refill?: boolean): ArrayBuffer;
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

