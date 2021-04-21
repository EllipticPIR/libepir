
import epir from './';

const time = () => new Date().getTime();

(async () => {
	// create_privkey().
	const privkey = epir.create_privkey();
	console.log('privkey:', privkey);
	// pubkey_from_privkey().
	const pubkey = epir.pubkey_from_privkey(privkey);
	console.log('privkey:', pubkey);
	// load_mG().
	console.log('The number of points in mG.bin:',
		(await epir.load_mG(`${process.env['HOME']}/.EllipticPIR/mG.bin`)).toLocaleString());
	// selector_create().
	const index_counts = new BigUint64Array(3);
	index_counts[0] = 1000n;
	index_counts[1] = 1000n;
	index_counts[2] = 1000n;
	const beginSelectorsCreate = time();
	const selector = epir.selector_create(pubkey, index_counts, 1024);
	console.log(`Selector created (normal) in ${(time() - beginSelectorsCreate).toLocaleString()}ms.`);
	// selector_create_fast().
	const beginSelectorsFastCreate = time();
	const selectorFast = epir.selector_create_fast(privkey, index_counts, 1024);
	console.log(`Selector created (fast) in ${(time() - beginSelectorsFastCreate).toLocaleString()}ms.`);
	// reply_decrypt().
	const beginDecrypt = time();
	const data = require('../src/test_napi_reply_data.json');
	const decrypted = await epir.reply_decrypt(new Uint8Array(data.reply), new Uint8Array(data.privkey), data.dimension, data.packing);
	for(let i=0; i<data.correct.length; i++) {
		if(decrypted[i] != data.correct[i]) {
			throw new Error('Decrypted is not correct.');
		}
	}
	console.log(`Reply decrypted in ${(time() - beginDecrypt).toLocaleString()}ms.`);
})();

