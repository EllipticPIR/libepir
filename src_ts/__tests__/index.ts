
import { MG_DEFAULT_PATH } from '../EpirBase';
import { createEpir, createDecryptionContext } from '../index';

test('create an Epir instance', async () => {
	await createEpir();
});

test('create a DecryptionContext instance', async () => {
	await createDecryptionContext(MG_DEFAULT_PATH);
});

