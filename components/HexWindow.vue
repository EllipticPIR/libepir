<template>
	<div>
		<p>{{ label }}</p>
		<textarea :value="value" rows="10" class="w-100" disabled />
		<p>Binary size: {{ (value.length / 2).toLocaleString() }} bytes</p>
		<p>Computation time: {{ time.toLocaleString() }} ms</p>
	</div>
</template>

<script lang="ts">
import Vue from 'vue';
export default Vue.extend({
	props: {
		label: String,
		value: String,
		time: Number,
	},
});
</script>

