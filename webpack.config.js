module.exports = {
	mode: 'production',
	entry: './src/wasm.ts',
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
	},
};
