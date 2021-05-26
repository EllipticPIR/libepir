
import { run as runECElGamal } from '../bench_ecelgamal';
import { run as runSelector } from '../bench_selector';
import { run as runReply } from '../bench_reply';

describe('bench', () => {
	test.concurrent.each([
		['ecelgamal', runECElGamal],
		['selector',  runSelector],
		['reply',     runReply],
	])('%s', async (name, run) => {
		console.log = () => {};
		expect(await run()).toBe(true);
	});
});

