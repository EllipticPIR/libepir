
import { runTests } from './test_common'
import { createEpir } from './wasm';

jest.setTimeout(30 * 1000);

runTests(createEpir);

