
export default {
	
	ssr: false,
	
	// Target: https://go.nuxtjs.dev/config-target
	target: 'static',
	
	// Global page headers: https://go.nuxtjs.dev/config-head
	head: {
		title: 'EllipticPIR client library',
	},
	
	// Global CSS: https://go.nuxtjs.dev/config-css
	css: [
	],
	
	// Plugins to run before rendering page: https://go.nuxtjs.dev/config-plugins
	plugins: [
	],
	
	// Auto import components: https://go.nuxtjs.dev/config-components
	components: true,
	
	// Modules for dev and build (recommended): https://go.nuxtjs.dev/config-modules
	buildModules: [
		// https://go.nuxtjs.dev/typescript
		'@nuxt/typescript-build',
		'@nuxtjs/vuetify',
	],
	
	// Modules: https://go.nuxtjs.dev/config-modules
	modules: [
	],
	
	// Build Configuration: https://go.nuxtjs.dev/config-build
	build: {
		extend(config, { isDev, isClient }) {
			config.module.rules.push(
				{
					test: /\.worker\.ts$/,
					loader: 'worker-loader',
				},
				{
					test: /\.ts$/,
					loader: 'ts-loader',
					options: {
						transpileOnly: true,
					},
				},
			);
			config.node = {
				fs: 'empty',
			};
			config.cache = true;
			if(isDev) {
				config.mode = 'development';
			}
		},
		babel: {
			compact: true,
		},
	},
	
	generate: {
		dir: 'build_nuxt',
	},
	
};

