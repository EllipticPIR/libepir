
import { runTests } from './addon_gen_mG';
import { createDecryptionContext } from '../wasm';

runTests(createDecryptionContext);

