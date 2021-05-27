
import { EpirBase, DecryptionContextBase, CIPHER_SIZE } from '../EpirBase';
import { createDecryptionContext } from '../addon';
import { createEpir } from '../wasm';
import { SelectorFactory, SelectorFactoryFast } from '../wasm.SelectorFactory';
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

let decCtx: DecryptionContextBase;
beforeAll(async () => {
	decCtx = await createDecryptionContext(`${process.env['HOME']}/.EllipticPIR/mG.bin`);
});

test('normal', async () => {
	const selectorFactory = new SelectorFactory(pubkey.buffer);
	await selectorFactory.fill();
	const selector = selectorFactory.create(index_counts, idx);
	expect(checkSelector(decCtx, privkey.buffer, index_counts, idx, selector)).toBe(true);
});

test('fast', async () => {
	const selectorFactory = new SelectorFactoryFast(privkey.buffer);
	await selectorFactory.fill();
	const selector = selectorFactory.create(index_counts, idx);
	expect(checkSelector(decCtx, privkey.buffer, index_counts, idx, selector)).toBe(true);
});

test('insufficient', async () => {
	const selectorFactory = new SelectorFactoryFast(privkey.buffer, [100, 10]);
	await selectorFactory.fill();
	expect(() => { selectorFactory.create(index_counts, idx) }).toThrow(/^Insufficient ciphers cache\.$/);
});

test('fill twice', async () => {
	const selectorFactory = new SelectorFactoryFast(privkey.buffer);
	await selectorFactory.fill();
	await selectorFactory.fill();
	const selector = selectorFactory.create(index_counts, idx);
	expect(checkSelector(decCtx, privkey.buffer, index_counts, idx, selector)).toBe(true);
});

test('don\'t refill', async () => {
	const selectorFactory = new SelectorFactoryFast(privkey.buffer);
	await selectorFactory.fill();
	const selector = selectorFactory.create(index_counts, idx, false);
	expect(checkSelector(decCtx, privkey.buffer, index_counts, idx, selector)).toBe(true);
});

