<template>
	<b-container>
		<h1>EllipticPIR Client Library (Browser Tests)</h1>
		
		<hr />
		
		<p>This page demonstrates the execution of the EllipticPIR Client Library.</p>
		
		<h2>Generate mG</h2>
		
		<div class="text-center">
			<b-button @click="generateMG">Generate mG</b-button>
		</div>
		
		<b-progress :max="mmax" height="2rem" animated class="my-4">
			<b-progress-bar :value="pointsComputed" style="font-size:150%;">
				<template v-if="pointsComputed != mmax">
					Computed {{ pointsComputed.toLocaleString() }} of {{ mmax.toLocaleString() }} points
				</template>
				<template v-else>
					(Completed)
				</template>
			</b-progress-bar>
		</b-progress>
		<p>Computation time: {{ generateMGTime.toLocaleString() }} ms</p>
		
		<h2>Generate a key pair</h2>
		
		<div class="text-center">
			<b-button @click="generatePrivkey">Generate private key</b-button>
		</div>
		
		<b-form-group label="Private Key">
			<b-form-input v-model="privkeyStr"></b-form-input>
		</b-form-group>
		
		<b-form-group label="Public Key">
			<b-form-input :value="pubkeyStr" disabled></b-form-input>
		</b-form-group>
		
		<h2>Specify index counts</h2>
		
		<b-form-group label="Index counts">
			<b-form-input v-model="indexCountsStr"></b-form-input>
		</b-form-group>
		
		<h2>Generate a selector (normal)</h2>
		
		<div class="text-center">
			<b-button @click="createSelector">Generate selector (normal)</b-button>
		</div>
		
		<div>
			<p>Selector (normal)</p>
			<textarea :value="selectorStr" rows="10" class="w-100" disabled />
			<p>Selector size: {{ (selectorStr.length / 2).toLocaleString() }} bytes</p>
			<p>Computation time: {{ createSelectorTime.toLocaleString() }} ms</p>
		</div>
		
		<h2>Generate a selector (fast)</h2>
		
		<div class="text-center">
			<b-button @click="createSelectorFast">Generate selector (fast)</b-button>
		</div>
		
		<div>
			<p>Selector (fast)</p>
			<textarea :value="selectorStrFast" rows="10" class="w-100" disabled />
			<p>Selector size: {{ (selectorStrFast.length / 2).toLocaleString() }} bytes</p>
			<p>Computation time: {{ createSelectorTimeFast.toLocaleString() }} ms</p>
		</div>
		
		<h2>Generate or input a database element</h2>
		
		<b-form-group label="Element size">
			<b-form-input v-model="elemSize" type="number" min="1" max="255"></b-form-input>
		</b-form-group>
		
		<div class="text-center">
			<b-button @click="generateElement">Generate random database element</b-button>
		</div>
		
		<div>
			<p>Element (hex)</p>
			<textarea v-model="elemStr" rows="5" class="w-100" />
		</div>
		
		<h2>Specify a dimension and a packing</h2>
		
		<b-form-group label="Dimension">
			<b-form-input v-model="dimension" type="number" min="1" max="10"></b-form-input>
		</b-form-group>
		
		<b-form-group label="Packing">
			<b-form-input v-model="packing" type="number" min="1" max="3"></b-form-input>
		</b-form-group>
		
		<h2>Compute a server's reply (mock)</h2>
		
		<div class="text-center">
			<b-button @click="computeReplyMock">Compute reply (mock)</b-button>
		</div>
		
		<div>
			<p>Reply</p>
			<textarea :value="replyStr" rows="10" class="w-100" disabled />
			<p>Reply size: {{ (replyStr.length / 2).toLocaleString() }} bytes</p>
			<p>Computation time: {{ computeReplyMockTime.toLocaleString() }} ms</p>
		</div>
		
		<h2>Decrypt the server's reply</h2>
		
		<div class="text-center">
			<b-button @click="decryptReply">Decrypt reply</b-button>
		</div>
		
		<div>
			<p>Decrypted</p>
			<textarea :value="decryptedStr" rows="5" class="w-100" disabled />
			<p>Computation time: {{ decryptReplyTime.toLocaleString() }} ms</p>
		</div>
		
		<h2>Debug Console</h2>
		<textarea id="console" :value="console.join('\n')" rows="20" class="w-100" disabled />
		
		<hr />
		
		<footer class="mb-4">
			Copyright &copy; EllipticPIR 2021. All rights reserved.
		</footer>
	</b-container>
</template>

<style type="text/css">
	h2 {
		margin-top: 4rem;
	}
</style>

<script lang="ts">
import Vue, { PropType } from 'vue'
import Dexie from 'dexie';

import { EpirBase, DecryptionContextBase, DEFAULT_MMAX, SCALAR_SIZE, POINT_SIZE } from '../src_ts/EpirBase';
import { createEpir, createDecryptionContext, getRandomBytes } from '../src_ts/wasm';

const time = () => new Date().getTime();

const uint8ArrayToHex = (arr: Uint8Array): string => {
	let ret = '';
	for(const n of arr) {
		ret += Number(n).toString(16).padStart(2, '0');
	}
	return ret;
};

const hexToUint8Array = (hex: string): Uint8Array => {
	return new Uint8Array(hex.match(/.{2}/g)!.map((h) => parseInt(h, 16)));
};

const checkIsHex = (hex: string, expectedSize: number = -1): boolean => {
	if(expectedSize >= 0) {
		return ((hex.length == 2 * expectedSize) && (hex.match(/^[0-9a-f]+$/) !== null));
	} else {
		return ((hex.length % 2 == 0) && (hex.match(/^[0-9a-f]+$/) !== null));
	}
};

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

export type DataType = {
	console: string[],
	epir: EpirBase | null,
	decCtx: DecryptionContextBase | null,
	pointsComputed: number,
	generateMGTime: number,
	mmax: number;
	privkeyStr: string,
	pubkeyStr: string,
	indexCountsStr: string,
	selectorStr: string,
	createSelectorTime: number,
	selectorStrFast: string,
	createSelectorTimeFast: number,
	dimension: string,
	packing: string,
	elemSize: number,
	elemStr: string,
	replyStr: string,
	computeReplyMockTime: number,
	decryptedStr: string,
	decryptReplyTime: number,
};

export default Vue.extend({
	data(): DataType {
		return {
			console: [],
			epir: null,
			decCtx: null,
			pointsComputed: 0,
			generateMGTime: -1,
			mmax: DEFAULT_MMAX,
			privkeyStr: '',
			pubkeyStr: '(failed to decode privkey)',
			indexCountsStr: '1000, 1000, 1000',
			selectorStr: '',
			createSelectorTime: -1,
			selectorStrFast: '',
			createSelectorTimeFast: -1,
			dimension: '3',
			packing: '3',
			elemSize: 32,
			elemStr: uint8ArrayToHex(getRandomBytes(32)),
			replyStr: '',
			computeReplyMockTime: -1,
			decryptedStr: '',
			decryptReplyTime: -1,
		}
	},
	watch: {
		privkeyStr(newPrivkeyStr) {
			if(checkIsHex(newPrivkeyStr, SCALAR_SIZE)) {
				this.pubkeyStr = uint8ArrayToHex(this.epir!.createPubkey(this.getPrivkey()));
			} else {
				this.pubkeyStr = '(failed to decode privkey)';
			}
		},
		elemStr(newElemStr) {
			if(checkIsHex(newElemStr)) {
				return;
			} else {
				this.elemSize = newElemStr.length / 2;
			}
		}
	},
	async mounted() {
		this.epir = await createEpir();
		this.generatePrivkey();
		this.decCtx = await this.loadMGIfExists();
	},
	updated() {
		const elem = this.$el.querySelector('#console');
		if(elem) {
			elem.scrollTop = elem.scrollHeight;
		}
	},
	methods: {
		log(str: string) {
			this.console.push(str);
		},
		getPrivkey() {
			if(!checkIsHex(this.privkeyStr, SCALAR_SIZE)) throw new Error('Invalid private key.');
			return hexToUint8Array(this.privkeyStr);
		},
		getPubkey() {
			if(!checkIsHex(this.pubkeyStr, POINT_SIZE)) throw new Error('Invalid public key.');
			return hexToUint8Array(this.pubkeyStr);
		},
		getIndexCounts() {
			return this.indexCountsStr.split(',').map((str) => parseInt(str));
		},
		getElem() {
			if(!checkIsHex(this.elemStr)) throw new Error('Invalid database element.');
			return hexToUint8Array(this.elemStr);
		},
		async loadMGIfExists() {
			const beginMG = time();
			const db = new MGDatabase();
			const mGDB = await db.mG.get(0);
			if(!mGDB) return null;
			const mCount = mGDB.value.length / 36;
			if(mCount != DEFAULT_MMAX) return null;
			const decCtx = await createDecryptionContext(mGDB.value);
			this.pointsComputed = mCount;
			this.generateMGTime = time() - beginMG;
			return decCtx;
		},
		async generateMG() {
			const beginMG = time();
			this.log('Generating mG..');
			const decCtx = await createDecryptionContext({ cb: (pointsComputed: number) => {
				this.pointsComputed = pointsComputed;
				const progress = 100 * pointsComputed / DEFAULT_MMAX;
				this.log(`Generated ${pointsComputed.toLocaleString()} of ${DEFAULT_MMAX.toLocaleString()} points (${progress.toFixed(2)}%)..`);
			}, interval: 10 * 1000 }, DEFAULT_MMAX);
			const db = new MGDatabase();
			await db.mG.put({ key: 0, value: decCtx.getMG() });
			this.generateMGTime = time() - beginMG;
			return decCtx;
		},
		generatePrivkey() {
			this.privkeyStr = uint8ArrayToHex(this.epir!.createPrivkey());
		},
		async createSelector() {
			try {
				const beginSelectorsCreate = time();
				const selector = await this.epir!.createSelector(this.getPubkey(), this.getIndexCounts(), 1024);
				this.selectorStr = uint8ArrayToHex(selector);
				this.createSelectorTime = time() - beginSelectorsCreate;
			} catch(e) {
				alert(e);
				this.log(e.stack);
			}
		},
		async createSelectorFast() {
			try {
				const beginSelectorsCreate = time();
				const selector = await this.epir!.createSelectorFast(this.getPrivkey(), this.getIndexCounts(), 1024);
				this.selectorStrFast = uint8ArrayToHex(selector);
				this.createSelectorTimeFast = time() - beginSelectorsCreate;
			} catch(e) {
				alert(e);
				this.log(e.stack);
			}
		},
		generateElement() {
			this.elemStr = uint8ArrayToHex(getRandomBytes(this.elemSize));
		},
		async computeReplyMock() {
			try {
				const beginReplyMock = time();
				const reply = this.epir!.computeReplyMock(this.getPubkey(), parseInt(this.dimension), parseInt(this.packing), this.getElem());
				this.replyStr = uint8ArrayToHex(reply);
				this.computeReplyMockTime = time() - beginReplyMock;
			} catch(e) {
				alert(e);
				this.log(e.stack);
			}
		},
		async decryptReply() {
			if(!this.decCtx) {
				alert('Please generate mG first.');
				return;
			}
			try {
				const beginDecrypt = time();
				const decrypted = await this.decCtx.decryptReply(
					this.getPrivkey(), parseInt(this.dimension), parseInt(this.packing), hexToUint8Array(this.replyStr));
				this.decryptedStr = uint8ArrayToHex(decrypted);
				this.decryptReplyTime = time() - beginDecrypt;
				const elem = hexToUint8Array(this.elemStr);
				for(let i=0; i<elem.length; i++) {
					if(decrypted[i] != elem[i]) {
						alert('Decrypted is not correct.');
						return;
					}
				}
			} catch(e) {
				alert(e);
				this.log(e.stack);
			}
		},
	},
})
</script>

