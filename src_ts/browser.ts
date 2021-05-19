
import Dexie from 'dexie';

import { DEFAULT_MMAX } from './EpirBase';
import { createEpir, createDecryptionContext } from './wasm';

const DIMENSION = 3;
const PACKING = 3;
const ELEM_SIZE = 32;

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
	const epir = await createEpir();
	// create_privkey().
	const privkey = epir.createPrivkey();
	log(`privkey: 0x${uint8ArrayToString(privkey)}`);
	// pubkey_from_privkey().
	const pubkey = epir.createPubkey(privkey);
	log(`pubkey:  0x${uint8ArrayToString(pubkey)}`);
	// load_mG().
	const beginMG = time();
	const db = new MGDatabase();
	const mGDB = await db.mG.get(0);
	const decCtx = await (async () => {
		if(mGDB) {
			return await createDecryptionContext(mGDB.value);
		} else {
			const decCtx = await createDecryptionContext({ cb: (points_computed: number) => {
				log(`Points computed: ${points_computed.toLocaleString()} of ${DEFAULT_MMAX.toLocaleString()} (${(100 * points_computed / DEFAULT_MMAX).toFixed(2)}%)`);
			}, interval: 100 * 1000 });
			await db.mG.put({ key: 0, value: decCtx.getMG() });
			return decCtx;
		}
	})();
	log(`mG.bin loaded in ${(time() - beginMG).toLocaleString()}ms.`);
	// selector_create().
	const index_counts = [1000, 1000, 1000];
	const beginSelectorsCreate = time();
	const selector = await epir.createSelector(pubkey, index_counts, 1024);
	log(`Selector created (normal) in ${(time() - beginSelectorsCreate).toLocaleString()}ms.`);
	// selector_create_fast().
	const beginSelectorsFastCreate = time();
	const selectorFast = await epir.createSelectorFast(privkey, index_counts, 1024);
	log(`Selector created (fast) in ${(time() - beginSelectorsFastCreate).toLocaleString()}ms.`);
	// reply_decrypt().
	const beginReplyMock = time();
	const elem = new Uint8Array(ELEM_SIZE);
	window.crypto.getRandomValues(elem);
	const reply = epir.computeReplyMock(pubkey, DIMENSION, PACKING, elem);
	log(`Reply data generated in ${(time() - beginReplyMock).toLocaleString()}ms.`);
	const beginDecrypt = time();
	const decrypted = await decCtx.decryptReply(
		privkey, DIMENSION, PACKING, new Uint8Array(reply));
	log(`Reply decrypted in ${(time() - beginDecrypt).toLocaleString()}ms.`);
	for(let i=0; i<ELEM_SIZE; i++) {
		if(decrypted[i] != elem[i]) {
			throw new Error('Decrypted is not correct.');
		}
	}
})();

