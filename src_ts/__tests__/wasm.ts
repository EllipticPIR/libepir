
import { runTests } from './addon';
import { createEpir, createDecryptionContext } from '../wasm';

runTests(createEpir, createDecryptionContext);

