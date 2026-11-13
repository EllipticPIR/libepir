<template>
	<div v-if="!inline" class="text-center">
		<v-btn :loading="loading" style="text-transform: none;" @click="onclick">{{ value }}</v-btn>
	</div>
	<v-btn v-else :loading="loading" style="text-transform: none;" @click="onclick">{{ value }}</v-btn>
</template>

<script setup lang="ts">
import { ref } from 'vue';

const props = withDefaults(defineProps<{
	value: string,
	click: () => unknown,
	inline?: boolean,
}>(), {
	inline: false,
});

const loading = ref(false);

const onclick = async () => {
	loading.value = true;
	try {
		await props.click();
	} finally {
		loading.value = false;
	}
};
</script>
