<template>
	<v-text-field
		:label="label" :value="value" @input="$emit('input', $event)" :type="type" :min="min" :max="max" :readonly="readonly" />
</template>

<style type="text-css">
input:read-only {
	background-color: #e9e9e9;
}
</style>

<script lang="ts">
import Vue from 'vue';
export default Vue.extend({
	props: {
		value: [String, Number],
		label: String,
		type: {
			type: String,
			default: 'text',
		},
		min: {
			type: String,
			default: '',
		},
		max: {
			type: String,
			default: '',
		},
		readonly: {
			type: Boolean,
			default: false,
		},
	},
});
</script>

