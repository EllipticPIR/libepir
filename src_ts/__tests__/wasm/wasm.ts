
import { runTests } from '../main';
import { createEpir, createDecryptionContext } from '../../wasm';

runTests(createEpir, createDecryptionContext);

