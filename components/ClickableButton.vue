<template>
	<div v-if="!inline" class="text-center">
		<v-btn @click="onclick" :loading="loading" style="text-transform: none;">{{ value }}</v-btn>
	</div>
	<v-btn v-else @click="onclick" :loading="loading" style="text-transform: none;">{{ value }}</v-btn>
</template>

<script lang="ts">
import Vue, { PropType } from 'vue';
export default Vue.extend({
	props: {
		value: String,
		click: Function as PropType<() => void>,
		inline: {
			type: Boolean,
			default: false,
		},
	},
	data(): { loading: boolean } {
		return {
			loading: false,
		};
	},
	methods: {
		async onclick() {
			this.loading = true;
			await this.click();
			this.loading = false;
		}
	},
});
</script>

