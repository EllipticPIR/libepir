
import { runTests } from '../main';
import { createEpir, createDecryptionContext } from '../../wasm';

// For WebAssembly tests, we have tests which uses max CPU cores (x2 for main threads and worker threads).
const testsWithWorkersCount = 4;
//process.setMaxListeners(testsWithWorkersCount * 2 * navigator.hardwareConcurrency);

runTests(createEpir, createDecryptionContext);

