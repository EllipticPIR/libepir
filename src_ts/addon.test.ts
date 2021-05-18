
import { runTests } from './test_common'
import { createEpir, createDecryptionContext } from './addon';

runTests(createEpir, createDecryptionContext);

