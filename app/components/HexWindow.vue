<template>
	<div>
		<v-textarea variant="filled" :label="label" :model-value="modelValue" :rows="rows" class="w-100" readonly />
		<p v-if="showSize">Binary size: {{ (modelValue.length / 2).toLocaleString() }} bytes</p>
		<p v-if="time >= 0">Computation time: {{ time.toLocaleString() }} ms</p>
		<p v-else>Computation time: (not executed)</p>
	</div>
</template>

<script setup lang="ts">
withDefaults(defineProps<{
	modelValue: string,
	label: string,
	time: number,
	rows?: string | number,
	showSize?: boolean,
}>(), {
	rows: 10,
	showSize: true,
});
</script>
