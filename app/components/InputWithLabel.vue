<template>
	<v-text-field
		:label="label" :model-value="modelValue" :type="type" :min="min" :max="max" :readonly="readonly"
		@update:model-value="emit('update:modelValue', $event)" />
</template>

<style>
input:read-only {
	background-color: #e9e9e9;
}
</style>

<script setup lang="ts">
withDefaults(defineProps<{
	modelValue: string | number,
	label: string,
	type?: string,
	min?: string,
	max?: string,
	readonly?: boolean,
}>(), {
	type: 'text',
	min: '',
	max: '',
	readonly: false,
});

const emit = defineEmits<{
	'update:modelValue': [value: string],
}>();
</script>
