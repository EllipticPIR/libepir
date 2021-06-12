
import { createEpir, createDecryptionContext } from '../../addon';
import { runTests } from '../main';

if(require.main === null) {
	runTests(createEpir, createDecryptionContext);
}

