
import { DecryptionContextCreateFunction } from '../EpirBase';
import { createDecryptionContext } from '../addon';
import { sha256sum } from './addon';

const MMAX = 1 << 16;

const mGHashSmall = new Uint8Array([
	0x8c, 0x55, 0x49, 0x7e, 0x28, 0xd5, 0xea, 0x75,
	0x15, 0xdd, 0x32, 0xb3, 0x98, 0x34, 0x0b, 0xfa,
	0xf8, 0x89, 0x40, 0x35, 0xe0, 0x30, 0xd2, 0x13,
	0x50, 0x80, 0x84, 0x31, 0xb8, 0x00, 0x8a, 0xf2
]);

export const runTests = (createDecryptionContext: DecryptionContextCreateFunction) => {
	describe('Generate mG', () => {
		test('without callback', async () => {
			const decCtx = await createDecryptionContext(undefined, MMAX);
			const mG = decCtx.getMG();
			expect(sha256sum(mG)).toEqual(mGHashSmall);
		});
		test('with callback', async () => {
			let pointsComputed = 0;
			const decCtx = await createDecryptionContext((pointsComputedTest: number) => {
				pointsComputed++;
				expect(pointsComputedTest).toBe(pointsComputed);
			}, MMAX);
			const mG = decCtx.getMG();
			expect(sha256sum(mG)).toEqual(mGHashSmall);
		}, 30 * 1000);
	});
};

if(require.main === null) {
	runTests(createDecryptionContext);
}

