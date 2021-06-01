<template>
	<div>
		<v-progress-linear v-if="showProgress" :value="100 * pointsComputed / mmax" color="blue" height="50" striped class="my-4">
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

<script lang="ts">
import Vue from 'vue';
import { time } from '../src_ts/util';
import { DecryptionContextBase, DEFAULT_MMAX, MG_SIZE } from '../src_ts/types';
import { createDecryptionContext, loadDecryptionContextFromIndexedDB, saveDecryptionContextToIndexedDB } from '../src_ts/wasm';
export default Vue.extend({
	props: {
		load: {
			type: [Function, null],
			default: null,
		},
		mmax: {
			type: Number,
			default: DEFAULT_MMAX,
		},
		reportInterval: {
			type: Number,
			default: 100 * 1000,
		},
		showProgress: {
			type: Boolean,
			default: true,
		},
		showLoadTime: {
			type: Boolean,
			default: false,
		},
		showComputeTime: {
			type: Boolean,
			default: false,
		},
		showSortTime: {
			type: Boolean,
			default: false,
		},
	},
	data() {
		return {
			pointsComputed: -1,
			pointsComputing: false,
			loadTime: -1,
			computeTime: -1,
			sortTime: -1,
		};
	},
	async created() {
		if(this.load) {
			this.load(await this.loadFromIndexedDB());
		}
	},
	methods: {
		formatTime(ms: number): string {
			if(ms < 0) return '(not executed)';
			return ms.toLocaleString() + ' ms';
		},
		async loadFromIndexedDB(): Promise<DecryptionContext | null> {
			const beginMG = time();
			const decCtx = await loadDecryptionContextFromIndexedDB();
			if(!decCtx) return null;
			const mmax = Math.floor(decCtx.getMG().byteLength / MG_SIZE);
			if(this.mmax != mmax) {
				return null;
			}
			this.pointsComputed = mmax;
			this.loadTime = time() - beginMG;
			return decCtx;
		},
		async generate(): Promise<DecryptionContext> {
			const beginCompute = time();
			this.pointsComputed = 0;
			this.pointsComputing = true;
			const decCtx = await createDecryptionContext({ cb: (pointsComputed: number) => {
				this.pointsComputed = pointsComputed;
				const progress = 100 * pointsComputed / this.mmax;
				if(pointsComputed === this.mmax) {
					this.computeTime = time() - beginCompute;
				}
			}, interval: this.reportInterval }, this.mmax);
			this.sortTime = time() - beginCompute - this.computeTime;
			saveDecryptionContextToIndexedDB(decCtx);
			this.loadTime = time() - beginCompute;
			this.pointsComputing = false;
			return decCtx;
		},
	},
});
</script>

