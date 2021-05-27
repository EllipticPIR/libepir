<template>
	<div>
		<v-textarea filled :label="label" :value="value" :rows="rows" class="w-100" readonly />
		<template v-if="showSize">
			<p>Binary size: {{ (value.length / 2).toLocaleString() }} bytes</p>
		</template>
		<template v-if="time >= 0">
			<p>Computation time: {{ time.toLocaleString() }} ms</p>
		</template>
		<template v-else>
			<p>Computation time: (not executed)</p>
		</template>
	</div>
</template>

<script lang="ts">
import Vue from 'vue';
export default Vue.extend({
	props: {
		label: String,
		value: String,
		time: Number,
		rows: {
			type: [String, Number],
			default: 10,
		},
		showSize: {
			type: Boolean,
			default: true,
		}
	},
});
</script>

