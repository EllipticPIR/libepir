
import { runTests } from './addon_gen_mG';
import { createDecryptionContext } from '../wasm';

// For WebAssembly tests, we have tests which uses max CPU cores (x2 for main threads and worker threads).
const testsWithWorkersCount = 3;
process.setMaxListeners(testsWithWorkersCount * 2 * navigator.hardwareConcurrency);

runTests(createDecryptionContext);

