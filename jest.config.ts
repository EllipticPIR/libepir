import type { Config } from 'jest';

const config: Config = {
	testEnvironment: 'jsdom',
	roots: [
		'<rootDir>/src_ts',
	],
	testMatch: [
		'**/__tests__/node/*.+(ts|tsx|js)',
		'**/?(*.)+(spec|test).+(ts|tsx|js)',
	],
	testPathIgnorePatterns: [
		'\\.setup\\.(ts|tsx|js)$',
	],
	transform: {
		'^.+\\.tsx?$': ['ts-jest', { tsconfig: 'tsconfig.test.json' }],
	},
	setupFilesAfterEnv: ['./src_ts/__tests__/crypto.setup.ts'],
	collectCoverageFrom: [
		'src_ts/**/*.ts',
		'!src_ts/**/__tests__/**/*.ts',
		'!src_ts/index.ts',
		// The browser (WASM + Web Worker) sources are not run by jest.
		'!src_ts/wasm*.ts',
	],
};

export default config;
