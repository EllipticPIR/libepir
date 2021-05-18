
import { runTests } from './test_common'
import { createEpir, createDecryptionContext } from './wasm';

runTests(createEpir, createDecryptionContext);

