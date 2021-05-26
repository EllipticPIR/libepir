
import { printMeasurement } from './util';
import { createEpir, createDecryptionContext } from './addon';

const indexCounts = [1000, 1000, 1000];

(async () => {
	const epir = await createEpir();
	const privkey = epir.createPrivkey();
	const pubkey = epir.createPubkey(privkey);
	const selector = await printMeasurement<ArrayBuffer>(() => {
		return epir.createSelector(pubkey, indexCounts, 12345);
	}, 'Selector (normal):');
	const selectorFast = await printMeasurement<ArrayBuffer>(() => {
		return epir.createSelectorFast(privkey, indexCounts, 12345);
	}, 'Selector (fast):');
})();

