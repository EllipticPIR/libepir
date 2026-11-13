
import 'fake-indexeddb/auto';

import { loadDecryptionContextFromIndexedDB, saveDecryptionContextToIndexedDB, createDecryptionContext } from '../../wasm';

describe('IndexedDB', () => {
	it('load (fail)', async () => {
		const decCtx = await loadDecryptionContextFromIndexedDB();
		expect(decCtx).toBe(null);
	});
	it('save', async () => {
		const decCtx = await createDecryptionContext(undefined, 1 << 8);
		await saveDecryptionContextToIndexedDB(decCtx);
	});
	it('load (success)', async () => {
		const decCtx = await loadDecryptionContextFromIndexedDB();
		expect(decCtx).not.toBe(null);
	});
});

