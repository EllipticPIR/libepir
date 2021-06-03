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
import { Vue, Component, Prop } from 'vue-property-decorator';
import { time } from '../src_ts/util';
import { DecryptionContextBase, DEFAULT_MMAX, MG_SIZE } from '../src_ts/types';
import { createDecryptionContext, loadDecryptionContextFromIndexedDB, saveDecryptionContextToIndexedDB } from '../src_ts/wasm';
@Component
export default class GenerateMG extends Vue {
	@Prop({ type: Function, default: null })
	public load!: ((...args: unknown[]) => unknown) | null;
	@Prop({ type: Number, default: DEFAULT_MMAX })
	public mmax!: number;
	@Prop({ type: Number, default: 100 * 1000 })
	public reportInterval!: number;
	@Prop({ type: Boolean, default: true })
	public showProgress!: boolean;
	@Prop({ type: Boolean, default: false })
	public showLoadTime!: boolean;
	@Prop({ type: Boolean, default: false })
	public showComputeTime!: boolean;
	@Prop({ type: Boolean, default: false })
	public showSortTime!: boolean;
	pointsComputed: number = -1;
	pointsComputing: boolean = false;
	loadTime: number = -1;
	computeTime: number = -1;
	sortTime: number = -1;
	async created() {
		if(this.load) {
			this.load(await this.loadFromIndexedDB());
		}
	}
	formatTime(ms: number): string {
		if(ms < 0) return '(not executed)';
		return ms.toLocaleString() + ' ms';
	}
	async loadFromIndexedDB(): Promise<DecryptionContextBase | null> {
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
	}
	async generate(): Promise<DecryptionContextBase> {
		const beginCompute = time();
		this.pointsComputed = 0;
		this.pointsComputing = true;
		const decCtx = await createDecryptionContext({ cb: (pointsComputed: number) => {
			this.pointsComputed = pointsComputed;
			if(pointsComputed === this.mmax) {
				this.computeTime = time() - beginCompute;
			}
		}, interval: this.reportInterval }, this.mmax);
		this.sortTime = time() - beginCompute - this.computeTime;
		saveDecryptionContextToIndexedDB(decCtx);
		this.loadTime = time() - beginCompute;
		this.pointsComputing = false;
		return decCtx;
	}
}
</script>

