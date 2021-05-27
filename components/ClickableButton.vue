<template>
	<div class="text-center">
		<v-btn @click="click" style="text-transform: none;">{{ value }}</v-btn>
	</div>
</template>

<script lang="ts">
import Vue from 'vue';
export default Vue.extend({
	props: {
		value: String,
		click: Function,
	},
});
</script>

