
import { MG_DEFAULT_PATH } from '../EpirBase';
import { createEpir, createDecryptionContext } from '../index';

test('create an Epir instance', async () => {
	const epir = await createEpir();
});

test('create a DecryptionContext instance', async () => {
	const decCtx = await createDecryptionContext(MG_DEFAULT_PATH);
});

