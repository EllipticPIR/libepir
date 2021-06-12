
require('fake-indexeddb/auto');

import { loadDecryptionContextFromIndexedDB, saveDecryptionContextToIndexedDB, createDecryptionContext } from '../../wasm';

require('fake-indexeddb/lib/FDBFactory');

// For WebAssembly tests, we have tests which uses max CPU cores (x2 for main threads and worker threads).
const testsWithWorkersCount = 2;
process.setMaxListeners(testsWithWorkersCount * 2 * navigator.hardwareConcurrency);

describe('IndexedDB', () => {
	test('load (fail)', async () => {
		const decCtx = await loadDecryptionContextFromIndexedDB();
		expect(decCtx).toBe(null);
	});
	test('save', async () => {
		const decCtx = await createDecryptionContext(undefined, 1 << 8);
		await saveDecryptionContextToIndexedDB(decCtx);
	});
	test('load (success)', async () => {
		const decCtx = await loadDecryptionContextFromIndexedDB();
		expect(decCtx).not.toBe(null);
	});
});

