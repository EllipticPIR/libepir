
/**
 * The Web Worker pool shared by Epir, DecryptionContext, SelectorFactory and mG generation.
 *
 * Every worker holds one instance of the Emscripten module, so the number of workers bounds the
 * number of WebAssembly memories the page allocates. By default the pool has
 * min(navigator.hardwareConcurrency, DEFAULT_MAX_WORKERS) workers; call setDefaultWorkerCount()
 * before the first use to change it.
 */

import { WorkerPool } from './workerpool';

export { WorkerPool };

/** Upper bound of the default worker count (many-core machines would otherwise exhaust wasm memory). */
export const DEFAULT_MAX_WORKERS = 16;

let defaultWorkerCount: number | undefined;
let defaultPool: WorkerPool | null = null;

export const createEpirWorker = (): Worker =>
	new Worker(new URL('./wasm.worker.ts', import.meta.url), { type: 'module' });

/** Creates a new (non-shared) pool of `size` workers. Call terminate() on it when no longer needed. */
export const createWorkerPool = (size: number): WorkerPool => new WorkerPool(size, createEpirWorker);

/** The default number of workers: min(navigator.hardwareConcurrency, DEFAULT_MAX_WORKERS), at least 1. */
export const getDefaultWorkerCount = (): number => {
	if(defaultWorkerCount !== undefined) return defaultWorkerCount;
	const hc = (typeof navigator !== 'undefined' && navigator.hardwareConcurrency) || 1;
	return Math.max(1, Math.min(hc, DEFAULT_MAX_WORKERS));
};

/**
 * Sets the size of the shared worker pool. Must be called before the pool is first used.
 * @throws RangeError for a non-positive or non-integer count, Error when the pool is already running.
 */
export const setDefaultWorkerCount = (count: number): void => {
	if(!Number.isInteger(count) || count < 1) {
		throw new RangeError('The worker count must be a positive integer.');
	}
	if(defaultPool) {
		throw new Error('The shared worker pool is already running; call setDefaultWorkerCount() before using the library.');
	}
	defaultWorkerCount = count;
};

/** The shared worker pool (created on first use). */
export const getDefaultWorkerPool = (): WorkerPool => {
	if(!defaultPool) defaultPool = createWorkerPool(getDefaultWorkerCount());
	return defaultPool;
};

/** Accepts either a pool or a worker count (which creates a dedicated pool). */
export const resolveWorkerPool = (workers?: WorkerPool | number): WorkerPool => {
	if(workers === undefined) return getDefaultWorkerPool();
	if(typeof workers === 'number') return createWorkerPool(workers);
	return workers;
};

