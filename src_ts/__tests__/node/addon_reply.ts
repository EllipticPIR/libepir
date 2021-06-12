
import { createEpir, createDecryptionContext } from '../../addon';
import { runTests } from '../reply';

if(require.main === null) {
	runTests(createEpir, createDecryptionContext);
}

