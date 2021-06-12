
import { createDecryptionContext, SelectorFactory } from '../../wasm';
import { runTests } from '../SelectorFactory';

runTests(
	(isFast: boolean, key: ArrayBuffer, capacities?: number[]) => new SelectorFactory(isFast, key, capacities),
	createDecryptionContext,
);

