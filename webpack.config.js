
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
				test: /\.worker\.ts$/,
				loader: 'worker-loader',
			},
			{
				test: /\.ts$/,
				loader: 'ts-loader',
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
		open: true,
		openPage: 'src/browser.html',
	},
};

