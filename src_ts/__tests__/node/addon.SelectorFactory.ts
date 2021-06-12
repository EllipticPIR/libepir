
import { createDecryptionContext, SelectorFactory } from '../../addon';
import { runTests } from '../SelectorFactory';

runTests(
	(isFast: boolean, key: ArrayBuffer, capacities?: number[]) => new SelectorFactory(isFast, key, capacities),
	createDecryptionContext,
);

