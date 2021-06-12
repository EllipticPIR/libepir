
export default {
	preset: 'ts-jest',
	testEnvironment: 'jsdom',
	roots: [
		'<rootDir>/src_ts',
	],
	testMatch: [
		'**/__tests__/**/*.+(ts|tsx|js)',
		'**/?(*.)+(spec|test).+(ts|tsx|js)',
	],
	testPathIgnorePatterns: [
		'\.setup\.(ts|tsx|js)$',
	],
	transform: {
		'^.+\\.worker.[t|j]sx?$': 'workerloader-jest-transformer',
	},
	setupFilesAfterEnv: ['./src_ts/__tests__/crypto.setup.ts'],
	collectCoverageFrom: [
		'src_ts/**/*.ts',
		'!src_ts/index.ts',
	],
};

