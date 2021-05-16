
import { createEpir } from './wasm'

describe('Browser', () => {
	
	it('create private key', async () => {
		Object.defineProperty(global.self, 'crypto', {
			value: {
				getRandomValues: (buf: Uint8Array) => buf.set(require('crypto').randomBytes(buf.length)),
			}
		});
		const epir = await createEpir();
		const privkey = epir.create_privkey();
		expect(privkey).toHaveLength(32);
	});
	
});

