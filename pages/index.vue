<template>
	<v-app>
		<v-main>
			<v-container>
				<h1>EllipticPIR Client Library (Browser Tests)</h1>
				
				<hr />
				
				<p>This page demonstrates the execution of the EllipticPIR Client Library.</p>
				
				<h2>Generate mG</h2>
				
				<ClickableButton value="Generate mG" :click="generateMG" />
				
				<v-progress-linear :value="100 * pointsComputed / mmax" color="blue" height="50" striped class="my-4">
					<strong>
						<template v-if="pointsComputed != mmax">
							{{ pointsComputed.toLocaleString() }} of {{ mmax.toLocaleString() }} points computed
						</template>
						<template v-else-if="pointsComputing">
							(Sorting...)
						</template>
						<template v-else>
							(Completed)
						</template>
					</strong>
				</v-progress-linear>
				<p>Load time: {{ mGLoadTime.toLocaleString() }} ms</p>
				<p>Compute time: {{ mGComputeTime.toLocaleString() }} ms</p>
				<p>Sort time: {{ mGSortTime.toLocaleString() }} ms</p>
				
				<h2>Generate a key pair</h2>
				
				<ClickableButton value="Generate Private Key" :click="generatePrivkey" />
				
				<InputWithLabel v-model="privkeyStr" label="Private Key" />
				<InputWithLabel v-model="pubkeyStr" label="Public Key" readonly />
				
				<h2>Specify index counts</h2>
				
				<InputWithLabel v-model="indexCountsStr" label="Index counts" />
				
				<p>Database elements: {{ getIndexCounts().reduce((acc, v) => acc * v, 1).toLocaleString() }}</p>
				
				<h2>Generate a selector</h2>
				
				<div class="text-center my-4">
					<ClickableButton inline class="mx-2" value="On-Demand, Normal" :click="createSelector" />
					<ClickableButton inline class="mx-2" value="On-Demand, Fast" :click="createSelectorFast" />
				</div>
				
				<div class="text-center my-4">
					<ClickableButton inline class="mx-2" value="Factory, Noraml" :click="createSelectorFromFactory" />
					<ClickableButton inline class="mx-2" value="Factory, Fast" :click="createSelectorFromFactoryFast" />
				</div>
				
				<p>
					SelectorFactory cache (normal):
					<template v-if="selectorFactory">
						zeros = {{ selectorFactory.ciphers[0].length.toLocaleString() }},
						ones = {{ selectorFactory.ciphers[1].length.toLocaleString() }}
					</template>
					<template v-else>
						(not available)
					</template>
				</p>
				
				<p>
					SelectorFactory cache (fast):
					<template v-if="selectorFactoryFast">
						zeros = {{ selectorFactoryFast.ciphers[0].length.toLocaleString() }},
						ones = {{ selectorFactoryFast.ciphers[1].length.toLocaleString() }}
					</template>
					<template v-else>
						(not available)
					</template>
				</p>
				
				<HexWindow v-model="selectorStr" label="Selector" :time="createSelectorTime" />
				
				<h2>Generate or input a database element</h2>
				
				<InputWithLabel v-model="elemSize" label="Element size" type="number" min="1" max="255" />
				
				<ClickableButton value="Generate Random Database Element" :click="generateElement" />
				
				<v-textarea outlined label="Element (hex)" v-model="elemStr" rows="5" class="w-100" />
				
				<h2>Specify a dimension and a packing</h2>
				
				<InputWithLabel v-model="dimension" label="Dimension" type="number" min="1" max="10" />
				<InputWithLabel v-model="packing" label="Packing" type="number" min="1" max="3" />
				
				<h2>Compute a server's reply (mock)</h2>
				
				<ClickableButton value="Compute Reply (mock)" :click="computeReplyMock" />
				
				<HexWindow v-model="replyStr" label="Reply" :time="computeReplyMockTime" />
				
				<h2>Decrypt the server's reply</h2>
				
				<ClickableButton value="Decrypt Reply" :click="decryptReply" />
				
				<HexWindow v-model="decryptedStr" label="Decrypted" :time="decryptReplyTime" rows="5" :show-size="false" />
				
				<hr />
				
				<footer class="mb-4">
					Copyright &copy; EllipticPIR 2021. All rights reserved.
				</footer>
			</v-container>
		</v-main>
	</v-app>
</template>

<style type="text/css">
	h2 {
		margin-top: 4rem;
	}
</style>

<script lang="ts">
import Vue from 'vue';

import { time, arrayBufferToHex, hexToArrayBuffer, getRandomBytes, checkIsHex } from '../src_ts/util';
import { EpirBase, DecryptionContextBase, DEFAULT_MMAX, SCALAR_SIZE, POINT_SIZE } from '../src_ts/EpirBase';
import {
	createEpir, createDecryptionContext,
	loadDecryptionContextFromIndexedDB, saveDecryptionContextToIndexedDB,
	SelectorFactory
} from '../src_ts/wasm';

export type DataType = {
	epir: EpirBase | null,
	decCtx: DecryptionContextBase | null,
	selectorFactory: SelectorFactory | null,
	selectorFactoryFast: SelectorFactory | null,
	pointsComputed: number,
	pointsComputing: boolean,
	mGLoadTime: number,
	mGComputeTime: number,
	mGSortTime: number,
	mmax: number;
	privkeyStr: string,
	pubkeyStr: string,
	indexCountsStr: string,
	selectorStr: string,
	createSelectorTime: number,
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
			epir: null,
			decCtx: null,
			selectorFactory: null,
			selectorFactoryFast: null,
			pointsComputed: 0,
			pointsComputing: false,
			mGLoadTime: -1,
			mGComputeTime: -1,
			mGSortTime: -1,
			mmax: DEFAULT_MMAX,
			privkeyStr: '',
			pubkeyStr: '(failed to decode privkey)',
			indexCountsStr: '1000, 1000, 1000',
			selectorStr: '',
			createSelectorTime: -1,
			dimension: '3',
			packing: '3',
			elemSize: 32,
			elemStr: '',
			replyStr: '',
			computeReplyMockTime: -1,
			decryptedStr: '',
			decryptReplyTime: -1,
		}
	},
	watch: {
		privkeyStr(newPrivkeyStr) {
			if(checkIsHex(newPrivkeyStr, SCALAR_SIZE)) {
				this.pubkeyStr = arrayBufferToHex(this.epir!.createPubkey(this.getPrivkey()));
				this.selectorFactory = new SelectorFactory(false, this.getPubkey());
				this.selectorFactoryFast = new SelectorFactory(true, this.getPrivkey());
				this.selectorFactory.fill();
				this.selectorFactoryFast.fill();
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
		this.elemStr = arrayBufferToHex(getRandomBytes(32));
		this.epir = await createEpir();
		this.generatePrivkey();
		await this.loadMGIfExists();
	},
	methods: {
		getPrivkey() {
			if(!checkIsHex(this.privkeyStr, SCALAR_SIZE)) throw new Error('Invalid private key.');
			return hexToArrayBuffer(this.privkeyStr);
		},
		getPubkey() {
			if(!checkIsHex(this.pubkeyStr, POINT_SIZE)) throw new Error('Invalid public key.');
			return hexToArrayBuffer(this.pubkeyStr);
		},
		getIndexCounts() {
			return this.indexCountsStr.split(',').map((str) => parseInt(str));
		},
		getElem() {
			if(!checkIsHex(this.elemStr)) throw new Error('Invalid database element.');
			return hexToArrayBuffer(this.elemStr);
		},
		async loadMGIfExists() {
			const beginMG = time();
			const decCtx = await loadDecryptionContextFromIndexedDB();
			if(!decCtx) return;
			this.decCtx = decCtx;
			this.pointsComputed = DEFAULT_MMAX;
			this.mGLoadTime = time() - beginMG;
		},
		async generateMG() {
			const beginCompute = time();
			this.pointsComputed = 0;
			this.pointsComputing = true;
			this.decCtx = await createDecryptionContext({ cb: (pointsComputed: number) => {
				this.pointsComputed = pointsComputed;
				const progress = 100 * pointsComputed / DEFAULT_MMAX;
				if(pointsComputed === DEFAULT_MMAX) {
					this.mGComputeTime = time() - beginCompute;
				}
			}, interval: 100 * 1000 }, DEFAULT_MMAX);
			this.mGSortTime = time() - beginCompute - this.mGComputeTime;
			saveDecryptionContextToIndexedDB(this.decCtx);
			this.mGLoadTime = time() - beginCompute;
			this.pointsComputing = false;
		},
		generatePrivkey() {
			this.privkeyStr = arrayBufferToHex(this.epir!.createPrivkey());
		},
		async createSelector() {
			try {
				const beginSelectorsCreate = time();
				const selector = await this.epir!.createSelector(this.getPubkey(), this.getIndexCounts(), 1024);
				this.createSelectorTime = time() - beginSelectorsCreate;
				this.selectorStr = arrayBufferToHex(selector);
			} catch(e) {
				alert(e);
				console.log(e.stack);
			}
		},
		async createSelectorFast() {
			try {
				const beginSelectorsCreate = time();
				const selector = await this.epir!.createSelectorFast(this.getPrivkey(), this.getIndexCounts(), 1024);
				this.createSelectorTime = time() - beginSelectorsCreate;
				this.selectorStr = arrayBufferToHex(selector);
			} catch(e) {
				alert(e);
				console.log(e.stack);
			}
		},
		async createSelectorFromFactory() {
			if(!this.selectorFactory) {
				alert('SelectorFactory is not initialized.');
				return;
			}
			try {
				const beginSelectorsCreate = time();
				const selector = this.selectorFactory.create(this.getIndexCounts(), 1024, false);
				this.createSelectorTime = time() - beginSelectorsCreate;
				this.selectorStr = arrayBufferToHex(selector);
				this.selectorFactory.fill();
			} catch(e) {
				alert(e);
				console.log(e.stack);
			}
		},
		async createSelectorFromFactoryFast() {
			if(!this.selectorFactoryFast) {
				alert('SelectorFactory is not initialized.');
				return;
			}
			try {
				const beginSelectorsCreate = time();
				const selector = this.selectorFactoryFast.create(this.getIndexCounts(), 1024, false);
				this.createSelectorTime = time() - beginSelectorsCreate;
				this.selectorStr = arrayBufferToHex(selector);
				this.selectorFactoryFast.fill();
			} catch(e) {
				alert(e);
				console.log(e.stack);
			}
		},
		generateElement() {
			this.elemStr = arrayBufferToHex(getRandomBytes(this.elemSize));
		},
		async computeReplyMock() {
			try {
				const beginReplyMock = time();
				const reply = this.epir!.computeReplyMock(this.getPubkey(), parseInt(this.dimension), parseInt(this.packing), this.getElem());
				this.replyStr = arrayBufferToHex(reply);
				this.computeReplyMockTime = time() - beginReplyMock;
			} catch(e) {
				alert(e);
				console.log(e.stack);
			}
		},
		async decryptReply() {
			if(!this.decCtx) {
				alert('Please generate mG first.');
				return;
			}
			if(!this.replyStr) {
				alert('Please run "Compute reply (mock)" first.');
				return;
			}
			try {
				const beginDecrypt = time();
				const decrypted = await this.decCtx.decryptReply(
					this.getPrivkey(), parseInt(this.dimension), parseInt(this.packing), hexToArrayBuffer(this.replyStr));
				this.decryptedStr = arrayBufferToHex(decrypted);
				this.decryptReplyTime = time() - beginDecrypt;
				const elem = hexToArrayBuffer(this.elemStr);
				const decryptedView = new Uint8Array(decrypted);
				const elemView = new Uint8Array(elem);
				for(let i=0; i<elemView.length; i++) {
					if(decryptedView[i] != elemView[i]) {
						alert('Decrypted is not correct.');
						return;
					}
				}
			} catch(e) {
				alert(e);
				console.log(e.stack);
			}
		},
	},
});
</script>

