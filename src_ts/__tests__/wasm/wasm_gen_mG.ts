
import { runTests } from '../gen_mG';
import { createDecryptionContext } from '../../wasm';

runTests(createDecryptionContext);

