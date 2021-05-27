
import { SelectorFactory } from '../wasm';
import { runTests } from './addon.SelectorFactory';

if(require.main === null) {
	runTests((isFast: boolean, key: ArrayBuffer, capacities?: number[]) => new SelectorFactory(isFast, key, capacities));
}

