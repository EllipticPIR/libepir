
const webpack = require('webpack');
const CopyPlugin = require('copy-webpack-plugin');

module.exports = {
	mode: 'production',
	entry: './src/browser.ts',
	output: {
		filename: 'bundle.js',
	},
	module: {
		rules: [
			{
				test: /\.ts$/,
				use: 'ts-loader',
			},
		],
	},
	resolve: {
		extensions: [
			'.ts', '.js',
		],
		fallback: {
			crypto: false,
			path: false,
			buffer: false,
			stream: false,
			fs: false,
		},
	},
	plugins: [
		new webpack.ProvidePlugin({
			process: 'process/browser',
		}),
		new CopyPlugin({
			patterns: [
				{ from: './build_em/src/epir.wasm', to: './epir.wasm' }
			],
		})
	]
};

