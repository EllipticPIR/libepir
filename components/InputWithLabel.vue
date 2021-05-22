<template>
	<b-form-group :label="label">
		<b-form-input :value="value" @input="$emit('input', $event)" :type="type" :min="min" :max="max" :disabled="disabled"></b-form-input>
	</b-form-group>
</template>

<script lang="ts">
import Vue from 'vue';
export default Vue.extend({
	props: {
		value: String | Number,
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
		disabled: {
			type: Boolean,
			default: false,
		},
	},
});
</script>

