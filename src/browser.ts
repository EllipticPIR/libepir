
import Dexie from 'dexie';

import epir_ from './wasm';

const time = () => new Date().getTime();

const MG_MAX = 1 << 24;

interface MGDatabaseElement {
	key: number;
	value: Uint8Array;
}

class MGDatabase extends Dexie {
	mG: Dexie.Table<MGDatabaseElement, number>;
	constructor() {
		super('mG.bin');
		this.version(1).stores({
			mG: 'key',
		});
		this.mG = this.table('mG');
	}
}

(async () => {
	const epir = await epir_();
	// create_privkey().
	const privkey = epir.create_privkey();
	console.log('privkey:', privkey);
	// pubkey_from_privkey().
	const pubkey = epir.pubkey_from_privkey(privkey);
	console.log('privkey:', pubkey);
	// load_mG().
	const db = new MGDatabase();
	const mGDB = await db.mG.get(0);
	const decCtx = await (async () => {
		if(mGDB) {
			return await epir.get_decryption_context(mGDB.value);
		} else {
			const decCtx = await epir.get_decryption_context();
			await db.mG.put({ key: 0, value: decCtx.getMG() });
			return decCtx;
		}
	})();
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
	decCtx.delete();
})();

