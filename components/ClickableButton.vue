<template>
	<div class="text-center">
		<v-btn @click="onclick" :loading="loading" style="text-transform: none;">{{ value }}</v-btn>
	</div>
</template>

<script lang="ts">
import Vue from 'vue';
export default Vue.extend({
	props: {
		value: String,
		click: Function,
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

