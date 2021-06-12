
import { createDecryptionContext } from '../../addon';
import { runTests } from '../gen_mG';

if(require.main === null) {
	runTests(createDecryptionContext);
}

