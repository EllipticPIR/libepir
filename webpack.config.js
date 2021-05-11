
const webpack = require('webpack');

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
			{
				test: /\.worker\.js$/,
				use: { loader: 'worker-loader' },
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
	],
	devServer: {
		headers: {
			'Cross-Origin-Embedder-Policy': 'require-corp',
			'Cross-Origin-Opener-Policy': 'same-origin',
		},
		open: true,
		openPage: 'src/browser.html',
	},
};

