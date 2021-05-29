
import { printMeasurement } from './util';
import { createEpir } from './addon';

export const INDEX_COUNTS = [1000, 1000, 1000];
export const IDX = 12345;

export const run = async (): Promise<boolean> => {
	const epir = await createEpir();
	const privkey = epir.createPrivkey();
	const pubkey = epir.createPubkey(privkey);
	await printMeasurement<ArrayBuffer>(() => {
		return epir.createSelector(pubkey, INDEX_COUNTS, IDX);
	}, 'Selector (normal):');
	await printMeasurement<ArrayBuffer>(() => {
		return epir.createSelectorFast(privkey, INDEX_COUNTS, IDX);
	}, 'Selector (fast):');
	return true;
};

/* istanbul ignore if  */
if(!module.parent) {
	run();
}

