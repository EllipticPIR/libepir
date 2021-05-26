
import { printMeasurement } from './util';
import { createEpir, createDecryptionContext } from './addon';

export const INDEX_COUNTS = [1000, 1000, 1000];
export const IDX = 12345;

export const run = async () => {
	const epir = await createEpir();
	const privkey = epir.createPrivkey();
	const pubkey = epir.createPubkey(privkey);
	const selector = await printMeasurement<ArrayBuffer>(() => {
		return epir.createSelector(pubkey, INDEX_COUNTS, IDX);
	}, 'Selector (normal):');
	const selectorFast = await printMeasurement<ArrayBuffer>(() => {
		return epir.createSelectorFast(privkey, INDEX_COUNTS, IDX);
	}, 'Selector (fast):');
	return true;
};

if(!module.parent) {
	run();
}

