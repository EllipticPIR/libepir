
import { createDecryptionContext, SelectorFactory } from '../../wasm';
import { runTests } from '../SelectorFactory';

if(require.main === null) {
	runTests(
		(isFast: boolean, key: ArrayBuffer, capacities?: number[]) => new SelectorFactory(isFast, key, capacities),
		createDecryptionContext,
	);
}

