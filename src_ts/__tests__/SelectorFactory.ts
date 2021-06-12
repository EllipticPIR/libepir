
import { DecryptionContextBase, DecryptionContextCreateFunction, SelectorFactoryBase, CIPHER_SIZE, MG_DEFAULT_PATH } from '../types';
import { privkey, pubkey, idx } from './main';

export const checkSelector = (
	decCtx: DecryptionContextBase, privkey: ArrayBuffer, indexCounts: number[], idx: number, selector: ArrayBuffer): boolean => {
	const nCiphers = indexCounts.reduce((acc, v) => acc + v, 0);
	if(selector.byteLength != nCiphers * CIPHER_SIZE) return false;
	let prod = indexCounts.reduce((acc, v) => acc * v, 1);
	let offset = 0;
	for(let ic=0; ic<indexCounts.length; ic++) {
		const cols = indexCounts[ic];
		prod /= cols;
		const rows = Math.floor(idx / prod);
		idx -= rows * prod;
		for(let r=0; r<cols; r++) {
			const msg = (r == rows ? 1 : 0);
			const decrypted = decCtx.decryptCipher(privkey, selector.slice(offset * CIPHER_SIZE, (offset + 1) * CIPHER_SIZE));
			if(decrypted != msg) return false;
			offset++;
		}
	}
	return true;
};

const INDEX_COUNTS = [100, 100, 100];
const CAPACITIES = [1000, 10];

export const runTests = (
		createSelectorFactory: (isFast: boolean, key: ArrayBuffer, capacities?: number[]) => SelectorFactoryBase,
		createDecryptionContext: DecryptionContextCreateFunction,
	): void => {
	
	const decCtxPromise = createDecryptionContext(MG_DEFAULT_PATH);
	
	test('normal', async () => {
		const decCtx = await decCtxPromise;
		const selectorFactory = createSelectorFactory(false, pubkey.buffer, CAPACITIES);
		await selectorFactory.fill();
		const selector = selectorFactory.create(INDEX_COUNTS, idx);
		expect(checkSelector(decCtx, privkey.buffer, INDEX_COUNTS, idx, selector)).toBe(true);
	});
	
	test('fast', async () => {
		const decCtx = await decCtxPromise;
		const selectorFactory = createSelectorFactory(true, privkey.buffer, CAPACITIES);
		await selectorFactory.fill();
		const selector = selectorFactory.create(INDEX_COUNTS, idx);
		expect(checkSelector(decCtx, privkey.buffer, INDEX_COUNTS, idx, selector)).toBe(true);
	});
	
	test('insufficient', async () => {
		const selectorFactory = createSelectorFactory(true, privkey.buffer, [100, 10]);
		await selectorFactory.fill();
		expect(() => { selectorFactory.create(INDEX_COUNTS, idx) }).toThrow(/^Insufficient ciphers cache\.$/);
	});
	
	test('fill twice', async () => {
		const decCtx = await decCtxPromise;
		const selectorFactory = createSelectorFactory(true, privkey.buffer, CAPACITIES);
		await selectorFactory.fill();
		await selectorFactory.fill();
		const selector = selectorFactory.create(INDEX_COUNTS, idx);
		expect(checkSelector(decCtx, privkey.buffer, INDEX_COUNTS, idx, selector)).toBe(true);
	});
	
	test('don\'t refill', async () => {
		const decCtx = await decCtxPromise;
		const selectorFactory = createSelectorFactory(true, privkey.buffer, CAPACITIES);
		await selectorFactory.fill();
		const selector = selectorFactory.create(INDEX_COUNTS, idx, false);
		expect(checkSelector(decCtx, privkey.buffer, INDEX_COUNTS, idx, selector)).toBe(true);
	});
};

