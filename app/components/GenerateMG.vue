<template>
	<div>
		<v-progress-linear v-if="showProgress" :model-value="100 * pointsComputed / mmax" color="blue" height="50" striped class="my-4">
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
		<div v-if="showLoadTime">Load time: {{ formatTime(loadTime) }}</div>
		<div v-if="showComputeTime">Compute time: {{ formatTime(computeTime) }}</div>
		<div v-if="showSortTime">Sort time: {{ formatTime(sortTime) }}</div>
	</div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { time } from '../../src_ts/util';
import { DecryptionContextBase, DEFAULT_MMAX, MG_SIZE } from '../../src_ts/types';
import { createDecryptionContext, loadDecryptionContextFromIndexedDB, saveDecryptionContextToIndexedDB } from '../../src_ts/wasm';

const props = withDefaults(defineProps<{
	load?: ((decCtx: DecryptionContextBase | null) => void) | null,
	mmax?: number,
	reportInterval?: number,
	showProgress?: boolean,
	showLoadTime?: boolean,
	showComputeTime?: boolean,
	showSortTime?: boolean,
}>(), {
	load: null,
	mmax: DEFAULT_MMAX,
	reportInterval: 100 * 1000,
	showProgress: true,
	showLoadTime: false,
	showComputeTime: false,
	showSortTime: false,
});

const pointsComputed = ref(-1);
const pointsComputing = ref(false);
const loadTime = ref(-1);
const computeTime = ref(-1);
const sortTime = ref(-1);

const formatTime = (ms: number): string => {
	if(ms < 0) return '(not executed)';
	return ms.toLocaleString() + ' ms';
};

const loadFromIndexedDB = async (): Promise<DecryptionContextBase | null> => {
	const beginMG = time();
	const decCtx = await loadDecryptionContextFromIndexedDB();
	if(!decCtx) return null;
	const mmax = Math.floor(decCtx.getMG().byteLength / MG_SIZE);
	if(props.mmax != mmax) {
		return null;
	}
	pointsComputed.value = mmax;
	loadTime.value = time() - beginMG;
	return decCtx;
};

const generate = async (): Promise<DecryptionContextBase> => {
	const beginCompute = time();
	pointsComputed.value = 0;
	pointsComputing.value = true;
	const decCtx = await createDecryptionContext({ cb: (computed: number) => {
		pointsComputed.value = computed;
		if(computed === props.mmax) {
			computeTime.value = time() - beginCompute;
		}
	}, interval: props.reportInterval }, props.mmax);
	sortTime.value = time() - beginCompute - computeTime.value;
	saveDecryptionContextToIndexedDB(decCtx);
	loadTime.value = time() - beginCompute;
	pointsComputing.value = false;
	return decCtx;
};

onMounted(async () => {
	if(props.load) {
		props.load(await loadFromIndexedDB());
	}
});

defineExpose({ generate });
</script>
