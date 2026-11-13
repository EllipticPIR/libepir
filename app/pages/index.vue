<template>
	<v-app>
		<v-main>
			<v-container>
				<h1>EllipticPIR Client Library (Browser Tests)</h1>
				
				<hr />
				
				<p>This page demonstrates the execution of the EllipticPIR Client Library.</p>
				
				<h2>Generate mG</h2>
				
				<ClickableButton value="Generate mG" :click="generateMG" />
				
				<GenerateMG ref="generateMGRef" :mmax="mmax" :load="(loaded) => { decCtx = loaded; }"
					:show-load-time="true" :show-compute-time="true" :show-sort-time="true" />
				
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
						zeros = {{ cacheSizes.normal[0].toLocaleString() }},
						ones = {{ cacheSizes.normal[1].toLocaleString() }}
					</template>
					<template v-else>
						(not available)
					</template>
				</p>
				
				<p>
					SelectorFactory cache (fast):
					<template v-if="selectorFactoryFast">
						zeros = {{ cacheSizes.fast[0].toLocaleString() }},
						ones = {{ cacheSizes.fast[1].toLocaleString() }}
					</template>
					<template v-else>
						(not available)
					</template>
				</p>
				
				<HexWindow v-model="selectorStr" label="Selector" :time="createSelectorTime" />
				
				<h2>Generate or input a database element</h2>
				
				<InputWithLabel v-model="elemSize" label="Element size" type="number" min="1" max="255" />
				
				<ClickableButton value="Generate Random Database Element" :click="generateElement" />
				
				<v-textarea variant="outlined" label="Element (hex)" v-model="elemStr" rows="5" class="w-100" />
				
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

<script setup lang="ts">
import { ref, shallowRef, watch, onMounted } from 'vue';

import { time, arrayBufferToHex, hexToArrayBuffer, getRandomBytes, checkIsHex } from '../../src_ts/util';
import { EpirBase, DecryptionContextBase, DEFAULT_MMAX, SCALAR_SIZE, POINT_SIZE } from '../../src_ts/types';
import { createEpir, SelectorFactory } from '../../src_ts/wasm';

// Objects holding Web Workers or WebAssembly memory must not be wrapped in deep reactive proxies.
const epir = shallowRef<EpirBase | null>(null);
const decCtx = shallowRef<DecryptionContextBase | null>(null);
const selectorFactory = shallowRef<SelectorFactory | null>(null);
const selectorFactoryFast = shallowRef<SelectorFactory | null>(null);
const cacheSizes = ref({ normal: [0, 0], fast: [0, 0] });
const generateMGRef = ref<{ generate: () => Promise<DecryptionContextBase> } | null>(null);

const mmax = DEFAULT_MMAX;
const privkeyStr = ref('');
const pubkeyStr = ref('(failed to decode privkey)');
const indexCountsStr = ref('1000, 1000, 1000');
const selectorStr = ref('');
const createSelectorTime = ref(-1);
const dimension = ref('3');
const packing = ref('3');
const elemSize = ref<string | number>(32);
const elemStr = ref('');
const replyStr = ref('');
const computeReplyMockTime = ref(-1);
const decryptedStr = ref('');
const decryptReplyTime = ref(-1);

const updateCacheSizes = () => {
	const sizes = (factory: SelectorFactory | null) => factory ? [factory.ciphers[0].length, factory.ciphers[1].length] : [0, 0];
	cacheSizes.value = { normal: sizes(selectorFactory.value), fast: sizes(selectorFactoryFast.value) };
};

const fillFactory = (factory: SelectorFactory) => {
	factory.fill().then(updateCacheSizes);
};

const getPrivkey = () => {
	if(!checkIsHex(privkeyStr.value, SCALAR_SIZE)) throw new Error('Invalid private key.');
	return hexToArrayBuffer(privkeyStr.value);
};

const getPubkey = () => {
	if(!checkIsHex(pubkeyStr.value, POINT_SIZE)) throw new Error('Invalid public key.');
	return hexToArrayBuffer(pubkeyStr.value);
};

const getIndexCounts = () => {
	return indexCountsStr.value.split(',').map((str) => parseInt(str));
};

const getElem = () => {
	if(!checkIsHex(elemStr.value)) throw new Error('Invalid database element.');
	return hexToArrayBuffer(elemStr.value);
};

const reportError = (e: unknown) => {
	alert(e);
	console.log(e instanceof Error ? e.stack : e);
};

watch(privkeyStr, (newPrivkeyStr) => {
	if(checkIsHex(newPrivkeyStr, SCALAR_SIZE)) {
		pubkeyStr.value = arrayBufferToHex(epir.value!.createPubkey(getPrivkey()));
		selectorFactory.value = new SelectorFactory(false, getPubkey());
		selectorFactoryFast.value = new SelectorFactory(true, getPrivkey());
		updateCacheSizes();
		fillFactory(selectorFactory.value);
		fillFactory(selectorFactoryFast.value);
	} else {
		pubkeyStr.value = '(failed to decode privkey)';
	}
});

watch(elemStr, (newElemStr) => {
	if(checkIsHex(newElemStr)) {
		return;
	} else {
		elemSize.value = newElemStr.length / 2;
	}
});

const generateMG = async () => {
	decCtx.value = await generateMGRef.value!.generate();
};

const generatePrivkey = () => {
	privkeyStr.value = arrayBufferToHex(epir.value!.createPrivkey());
};

const createSelectorWith = async (create: () => Promise<ArrayBuffer>) => {
	try {
		const beginSelectorsCreate = time();
		const selector = await create();
		createSelectorTime.value = time() - beginSelectorsCreate;
		selectorStr.value = arrayBufferToHex(selector);
	} catch(e) {
		reportError(e);
	}
};

const createSelector = () => createSelectorWith(
	() => epir.value!.createSelector(getPubkey(), getIndexCounts(), 1024));

const createSelectorFast = () => createSelectorWith(
	() => epir.value!.createSelectorFast(getPrivkey(), getIndexCounts(), 1024));

const createSelectorFromFactoryWith = async (factory: SelectorFactory | null) => {
	if(!factory) {
		alert('SelectorFactory is not initialized.');
		return;
	}
	await createSelectorWith(async () => factory.create(getIndexCounts(), 1024, false));
	updateCacheSizes();
	fillFactory(factory);
};

const createSelectorFromFactory = () => createSelectorFromFactoryWith(selectorFactory.value);

const createSelectorFromFactoryFast = () => createSelectorFromFactoryWith(selectorFactoryFast.value);

const generateElement = () => {
	elemStr.value = arrayBufferToHex(getRandomBytes(Number(elemSize.value)));
};

const computeReplyMock = async () => {
	try {
		const beginReplyMock = time();
		const reply = epir.value!.computeReplyMock(getPubkey(), parseInt(dimension.value), parseInt(packing.value), getElem());
		replyStr.value = arrayBufferToHex(reply);
		computeReplyMockTime.value = time() - beginReplyMock;
	} catch(e) {
		reportError(e);
	}
};

const decryptReply = async () => {
	if(!decCtx.value) {
		alert('Please generate mG first.');
		return;
	}
	if(!replyStr.value) {
		alert('Please run "Compute reply (mock)" first.');
		return;
	}
	try {
		const beginDecrypt = time();
		const decrypted = await decCtx.value.decryptReply(
			getPrivkey(), parseInt(dimension.value), parseInt(packing.value), hexToArrayBuffer(replyStr.value));
		decryptedStr.value = arrayBufferToHex(decrypted);
		decryptReplyTime.value = time() - beginDecrypt;
		const elemView = new Uint8Array(hexToArrayBuffer(elemStr.value));
		const decryptedView = new Uint8Array(decrypted);
		for(let i=0; i<elemView.length; i++) {
			if(decryptedView[i] != elemView[i]) {
				alert('Decrypted is not correct.');
				return;
			}
		}
	} catch(e) {
		reportError(e);
	}
};

onMounted(async () => {
	elemStr.value = arrayBufferToHex(getRandomBytes(32));
	epir.value = await createEpir();
	generatePrivkey();
});
</script>
