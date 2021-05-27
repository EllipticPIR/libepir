
import { randomFillSync } from 'crypto';

Object.defineProperty(global.self, 'crypto', {
	value: {
		getRandomValues: (buf: Uint8Array) => randomFillSync(buf),
	},
});

