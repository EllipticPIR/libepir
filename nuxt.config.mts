import vuetify from 'vite-plugin-vuetify';
import wasm from 'vite-plugin-wasm';

export default defineNuxtConfig({
	
	compatibilityDate: '2026-11-13',
	
	// The demo runs entirely in the browser (Web Workers + WebAssembly).
	ssr: false,
	
	app: {
		head: {
			title: 'EllipticPIR client library',
		},
	},
	
	css: ['vuetify/styles'],
	
	build: {
		transpile: ['vuetify'],
	},
	
	vite: {
		plugins: [
			// src_rs/pkg (wasm-pack --target bundler) imports the .wasm file as an ES module.
			wasm(),
			vuetify({ autoImport: true }),
		],
		worker: {
			format: 'es',
			plugins: () => [wasm()],
		},
		build: {
			target: 'esnext',
		},
	},
	
	nitro: {
		output: {
			publicDir: 'build_nuxt',
		},
	},
	
});
