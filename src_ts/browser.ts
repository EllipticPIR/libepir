
import Dexie from 'dexie';

import { epir as epir_, MMAX } from './wasm';

const time = () => new Date().getTime();

const uint8ArrayToString = (arr: Uint8Array) => {
	let ret = '';
	for(const n of arr) {
		ret += Number(n).toString(16).padStart(2, '0');
	}
	return ret;
};

const log = (str: string) => {
	console.log(str);
	const cons = <HTMLInputElement>document.getElementById('console');
	if(!cons) return;
	cons.value += str + '\n';
	cons.scrollTop = cons.scrollHeight;
}

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
	log(`privkey: 0x${uint8ArrayToString(privkey)}`);
	// pubkey_from_privkey().
	const pubkey = epir.pubkey_from_privkey(privkey);
	log(`pubkey:  0x${uint8ArrayToString(pubkey)}`);
	// load_mG().
	const beginMG = time();
	const db = new MGDatabase();
	const mGDB = await db.mG.get(0);
	const decCtx = await (async () => {
		if(mGDB) {
			return await epir.get_decryption_context(mGDB.value);
		} else {
			if(!epir.get_mG) throw new Error('Failed to call get_mG().');
			const mG = await epir.get_mG((points_computed: number) => {
				if(points_computed % (10 * 1000) == 0) {
					log(`Points computed: ${points_computed.toLocaleString()} of ${MMAX.toLocaleString()} (${(100 * points_computed / MMAX).toFixed(2)}%)`);
				}
			});
			await db.mG.put({ key: 0, value: mG });
			return await epir.get_decryption_context(mG);
		}
	})();
	log(`mG.bin loaded in ${(time() - beginMG).toLocaleString()}ms.`);
	// selector_create().
	const index_counts = [1000, 1000, 1000];
	const beginSelectorsCreate = time();
	const selector = await epir.selector_create(pubkey, index_counts, 1024);
	log(`Selector created (normal) in ${(time() - beginSelectorsCreate).toLocaleString()}ms.`);
	// selector_create_fast().
	const beginSelectorsFastCreate = time();
	const selectorFast = await epir.selector_create_fast(privkey, index_counts, 1024);
	log(`Selector created (fast) in ${(time() - beginSelectorsFastCreate).toLocaleString()}ms.`);
	// reply_decrypt().
	const data = require('../src/bench_js_reply_data.json');
	const beginDecrypt = time();
	const decrypted = await epir.reply_decrypt(
		decCtx, new Uint8Array(data.reply), new Uint8Array(data.privkey), data.dimension, data.packing);
	log(`Reply decrypted in ${(time() - beginDecrypt).toLocaleString()}ms.`);
	for(let i=0; i<data.correct.length; i++) {
		if(decrypted[i] != data.correct[i]) {
			throw new Error('Decrypted is not correct.');
		}
	}
})();

