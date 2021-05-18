
import { createEpir, createDecryptionContext } from './index';

test('create an Epir instance', async () => {
	const epir = await createEpir();
});

test('create a DecryptionContext instance', async () => {
	const decCtx = await createDecryptionContext(`${process.env['HOME']}/.EllipticPIR/mG.bin`);
});

