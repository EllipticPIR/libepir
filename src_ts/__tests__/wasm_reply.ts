
import { runTests } from './addon_reply';
import { createEpir, createDecryptionContext } from '../wasm';

runTests(createEpir, createDecryptionContext);

