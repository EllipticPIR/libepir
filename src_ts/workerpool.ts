
/**
 * A fixed-size pool of Web Workers with request/response matching.
 *
 * Every request gets an `id`; the worker must echo it in each message it posts back:
 * - `{ id, ...result }` resolves the request,
 * - `{ id, error: string }` rejects it (the worker stays in service),
 * - `{ id, progress: true, ... }` is passed to the request's progress callback (any number of times).
 * Several requests may be in flight on the same worker at once; a worker handles its messages in order.
 *
 * When a worker fails (`onerror` / `onmessageerror`), the requests pending on it are rejected, the worker is
 * terminated and a new one is started in its place. A slot is restarted at most `maxRestarts` times in a row
 * (the count is reset once the slot answers a request successfully), so a worker that fails at every start
 * (e.g. `WebAssembly.instantiate()` running out of memory) cannot cause an endless loop. After that the slot
 * is marked as failed, and every request routed to it is rejected at once, with the original error as `cause`.
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

export interface WorkerLike {
	postMessage(message: any, transfer: Transferable[]): void;
	terminate(): void;
	onmessage: ((ev: MessageEvent) => any) | null;
	onerror: ((ev: ErrorEvent) => any) | null;
	onmessageerror: ((ev: MessageEvent) => any) | null;
}

export type WorkerResponse = { [key: string]: any };

export interface WorkerPoolOptions {
	/** How many times in a row a failed worker slot is restarted before it is marked as failed. Default: 1. */
	maxRestarts?: number;
}

interface PendingRequest {
	worker: number;
	resolve: (data: WorkerResponse) => void;
	reject: (err: Error) => void;
	onProgress?: (data: WorkerResponse) => void;
}

export class WorkerPool {

	private readonly workers: WorkerLike[] = [];
	private readonly restarts: number[] = [];
	private readonly failures: (Error | null)[] = [];
	private readonly pending = new Map<number, PendingRequest>();
	private readonly maxRestarts: number;
	private nextId = 1;
	private terminated = false;

	constructor(public readonly size: number, private readonly createWorker: () => WorkerLike, options: WorkerPoolOptions = {}) {
		if(!Number.isInteger(size) || size < 1) {
			throw new RangeError('The worker pool size must be a positive integer.');
		}
		const maxRestarts = (options.maxRestarts === undefined ? 1 : options.maxRestarts);
		if(!Number.isInteger(maxRestarts) || maxRestarts < 0) {
			throw new RangeError('maxRestarts must be a non-negative integer.');
		}
		this.maxRestarts = maxRestarts;
		for(let i=0; i<size; i++) {
			this.workers.push(this.spawn(i));
			this.restarts.push(0);
			this.failures.push(null);
		}
	}

	/** The number of requests that have not been answered yet. */
	get pendingCount(): number {
		return this.pending.size;
	}

	/** The number of worker slots that are not marked as failed. */
	get availableCount(): number {
		return this.failures.filter((f) => f === null).length;
	}

	/**
	 * Sends `message` (plus a generated `id`) to the worker `worker % size`.
	 * @returns the worker's final response. Rejected at once when the pool was terminated or the slot has failed.
	 */
	run(worker: number, message: WorkerResponse, transfer: Transferable[] = [], onProgress?: (data: WorkerResponse) => void): Promise<WorkerResponse> {
		if(this.terminated) {
			return Promise.reject(new Error('The worker pool has been terminated.'));
		}
		const index = worker % this.size;
		const failure = this.failures[index];
		if(failure) {
			return Promise.reject(new Error(`Web Worker #${index} is unavailable: ${failure.message}`, { cause: failure }));
		}
		const id = this.nextId++;
		return new Promise<WorkerResponse>((resolve, reject) => {
			this.pending.set(id, { worker: index, resolve, reject, onProgress });
			try {
				this.workers[index].postMessage({ ...message, id }, transfer);
			} catch(e) {
				this.pending.delete(id);
				reject(e instanceof Error ? e : new Error(String(e)));
			}
		});
	}

	/** Terminates all workers and rejects every pending request. */
	terminate(): void {
		if(this.terminated) return;
		this.terminated = true;
		for(const worker of this.workers) worker.terminate();
		const err = new Error('The worker pool has been terminated.');
		for(const [id, p] of this.pending) {
			this.pending.delete(id);
			p.reject(err);
		}
	}

	private spawn(index: number): WorkerLike {
		const worker = this.createWorker();
		worker.onmessage = (ev) => this.onMessage(index, ev.data);
		worker.onerror = (ev) => {
			this.onWorkerFailed(index, worker, new Error(`Web Worker #${index} failed: ${(ev && ev.message) || 'unknown error'}`));
		};
		worker.onmessageerror = () => {
			this.onWorkerFailed(index, worker, new Error(`Web Worker #${index} sent a message that could not be deserialized.`));
		};
		return worker;
	}

	private onMessage(index: number, data: WorkerResponse): void {
		const p = (data && typeof data.id === 'number' ? this.pending.get(data.id) : undefined);
		if(!p) return;
		if(data.progress) {
			if(p.onProgress) p.onProgress(data);
			return;
		}
		this.pending.delete(data.id);
		if(data.error !== undefined) {
			p.reject(new Error(String(data.error)));
		} else {
			// The slot works: a later failure may restart it again.
			this.restarts[index] = 0;
			p.resolve(data);
		}
	}

	private onWorkerFailed(index: number, worker: WorkerLike, err: Error): void {
		// Ignore late events from a worker that has already been replaced.
		if(this.terminated || this.workers[index] !== worker) return;
		for(const [id, p] of this.pending) {
			if(p.worker !== index) continue;
			this.pending.delete(id);
			p.reject(err);
		}
		try {
			worker.terminate();
		} catch {
			// The worker is gone either way.
		}
		if(this.restarts[index] < this.maxRestarts) {
			this.restarts[index]++;
			try {
				this.workers[index] = this.spawn(index);
				return;
			} catch(e) {
				err = new Error(`Web Worker #${index} could not be restarted: ${e instanceof Error ? e.message : String(e)}`, { cause: err });
			}
		}
		this.failures[index] = err;
	}

}

