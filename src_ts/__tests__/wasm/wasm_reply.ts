
import { runTests } from '../reply';
import { createEpir, createDecryptionContext } from '../../wasm';

runTests(createEpir, createDecryptionContext);

