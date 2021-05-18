
import { Epir } from './wasm'

describe('Browser', () => {
	
	it('create private key', async () => {
		Object.defineProperty(global.self, 'crypto', {
			value: {
				getRandomValues: (buf: Uint8Array) => buf.set(require('crypto').randomBytes(buf.length)),
			}
		});
		const epir = new Epir();
		await epir.init();
		const privkey = epir.createPrivkey();
		expect(privkey).toHaveLength(32);
	});
	
});

