
import epir_t from './epir_t';
import epir_ from './addon';

test('create private key', async () => {
	const epir = await epir_();
	const privkey = epir.create_privkey();
	expect(privkey).toHaveLength(32);
});

test('create public key', async () => {
	const epir = await epir_();
	const privkey = epir.create_privkey();
	const pubkey = epir.pubkey_from_privkey(privkey);
	expect(pubkey).toHaveLength(32);
});

test('load mG', async () => {
	const epir = await epir_();
	const decCtx = await epir.get_decryption_context(`${process.env['HOME']}/.EllipticPIR/mG.bin`);
});

test('create selector (normal)', async () => {
	const epir = await epir_();
	const privkey = epir.create_privkey();
	const pubkey = epir.pubkey_from_privkey(privkey);
	const index_counts = [1000, 1000, 1000];
	const selector = await epir.selector_create(pubkey, index_counts, 1024);
	expect(selector).toHaveLength(3000 * 64);
});

test('create selector (fast)', async () => {
	const epir = await epir_();
	const privkey = epir.create_privkey();
	const index_counts = [1000, 1000, 1000];
	const selector = await epir.selector_create_fast(privkey, index_counts, 1024);
	expect(selector).toHaveLength(3000 * 64);
});

test('decrypt a reply', async () => {
	const data = require('./bench_js_reply_data.json');
	const epir = await epir_();
	const decCtx = await epir.get_decryption_context(`${process.env['HOME']}/.EllipticPIR/mG.bin`);
	const decrypted = await epir.reply_decrypt(
		decCtx, new Uint8Array(data.reply), new Uint8Array(data.privkey), data.dimension, data.packing);
	expect(new Uint8Array(decrypted.subarray(0, data.correct.length))).toEqual(new Uint8Array(data.correct));
});

