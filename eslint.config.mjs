import js from '@eslint/js';
import tsParser from '@typescript-eslint/parser';
import tsPlugin from '@typescript-eslint/eslint-plugin';

export default [
	js.configs.recommended,
	...tsPlugin.configs['flat/recommended'],
	{
		files: ['**/*.ts'],
		languageOptions: {
			parser: tsParser,
		},
	},
];
