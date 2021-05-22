<template>
	<div class="text-center">
		<b-button @click="click">{{ value }}</b-button>
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

