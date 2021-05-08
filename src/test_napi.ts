
import epir_ from './addon';

const time = () => new Date().getTime();

(async () => {
	const epir = await epir_();
	// create_privkey().
	const privkey = epir.create_privkey();
	console.log('privkey:', privkey);
	// pubkey_from_privkey().
	const pubkey = epir.pubkey_from_privkey(privkey);
	console.log('privkey:', pubkey);
	// load_mG().
	const beginMG = time();
	console.log('Loading mG.bin...');
	const decCtx = await epir.get_decryption_context(`${process.env['HOME']}/.EllipticPIR/mG.bin`);
	console.log(`mG.bin loaded in ${(time() - beginMG).toLocaleString()}ms.`);
	// selector_create().
	const index_counts = [1000, 1000, 1000];
	const beginSelectorsCreate = time();
	const selector = await epir.selector_create(pubkey, index_counts, 1024);
	console.log(`Selector created (normal) in ${(time() - beginSelectorsCreate).toLocaleString()}ms.`);
	// selector_create_fast().
	const beginSelectorsFastCreate = time();
	const selectorFast = await epir.selector_create_fast(privkey, index_counts, 1024);
	console.log(`Selector created (fast) in ${(time() - beginSelectorsFastCreate).toLocaleString()}ms.`);
	// reply_decrypt().
	const data = require('../src/test_napi_reply_data.json');
	const beginDecrypt = time();
	const decrypted = await epir.reply_decrypt(
		decCtx, new Uint8Array(data.reply), new Uint8Array(data.privkey), data.dimension, data.packing);
	console.log(`Reply decrypted in ${(time() - beginDecrypt).toLocaleString()}ms.`);
	for(let i=0; i<data.correct.length; i++) {
		if(decrypted[i] != data.correct[i]) {
			throw new Error('Decrypted is not correct.');
		}
	}
})();

