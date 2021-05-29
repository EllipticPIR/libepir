
import { DecryptionContextBase, SelectorFactoryBase, CIPHER_SIZE, MG_DEFAULT_PATH } from '../types';
import { createDecryptionContext, SelectorFactory } from '../addon';
import { privkey, pubkey, index_counts, idx } from './addon';

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

export const runTests = (
	createSelectorFactory: (isFast: boolean, key: ArrayBuffer, capacities?: number[]) => SelectorFactoryBase): void => {
	let decCtx: DecryptionContextBase;
	beforeAll(async () => {
		decCtx = await createDecryptionContext(MG_DEFAULT_PATH);
	});
	
	test('normal', async () => {
		const selectorFactory = createSelectorFactory(false, pubkey.buffer);
		await selectorFactory.fill();
		const selector = selectorFactory.create(index_counts, idx);
		expect(checkSelector(decCtx, privkey.buffer, index_counts, idx, selector)).toBe(true);
	});
	
	test('fast', async () => {
		const selectorFactory = createSelectorFactory(true, privkey.buffer);
		await selectorFactory.fill();
		const selector = selectorFactory.create(index_counts, idx);
		expect(checkSelector(decCtx, privkey.buffer, index_counts, idx, selector)).toBe(true);
	});
	
	test('insufficient', async () => {
		const selectorFactory = createSelectorFactory(true, privkey.buffer, [100, 10]);
		await selectorFactory.fill();
		expect(() => { selectorFactory.create(index_counts, idx) }).toThrow(/^Insufficient ciphers cache\.$/);
	});
	
	test('fill twice', async () => {
		const selectorFactory = createSelectorFactory(true, privkey.buffer);
		await selectorFactory.fill();
		await selectorFactory.fill();
		const selector = selectorFactory.create(index_counts, idx);
		expect(checkSelector(decCtx, privkey.buffer, index_counts, idx, selector)).toBe(true);
	});
	
	test('don\'t refill', async () => {
		const selectorFactory = createSelectorFactory(true, privkey.buffer);
		await selectorFactory.fill();
		const selector = selectorFactory.create(index_counts, idx, false);
		expect(checkSelector(decCtx, privkey.buffer, index_counts, idx, selector)).toBe(true);
	});
};

if(require.main === null) {
	runTests((isFast: boolean, key: ArrayBuffer, capacities?: number[]) => new SelectorFactory(isFast, key, capacities));
}

