
module.exports = {
	roots: [
		'<rootDir>/src_ts',
	],
	testMatch: [
		'**/__tests__/**/*.+(ts|tsx|js)',
		'**/?(*.)+(spec|test).+(ts|tsx|js)',
	],
	transform: {
		'^.+\\.worker.[t|j]sx?$': 'workerloader-jest-transformer',
		'^.+\\.(ts|tsx)$': 'ts-jest',
	},
	collectCoverageFrom: [
		'src_ts/**/*.ts',
		'!src_ts/index.ts',
		'!src_ts/browser.ts',
		'!src_ts/test_common.ts',
	],
};

