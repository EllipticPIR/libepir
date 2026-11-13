
/**
 * A fixed-size pool of Web Workers with request/response matching.
 *
 * Every request gets an `id`; the worker must echo it in each message it posts back:
 * - `{ id, ...result }` resolves the request,
 * - `{ id, error: string }` rejects it,
 * - `{ id, progress: true, ... }` is passed to the request's progress callback (any number of times).
 * Several requests may be in flight on the same worker at once; a worker handles its messages in order.
 *
 * When a worker reports an error (`onerror` / `onmessageerror`), all requests pending on that worker are
 * rejected instead of waiting forever.
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

interface PendingRequest {
	worker: number;
	resolve: (data: WorkerResponse) => void;
	reject: (err: Error) => void;
	onProgress?: (data: WorkerResponse) => void;
}

export class WorkerPool {

	private readonly workers: WorkerLike[] = [];
	private readonly pending = new Map<number, PendingRequest>();
	private nextId = 1;
	private terminated = false;

	constructor(public readonly size: number, createWorker: () => WorkerLike) {
		if(!Number.isInteger(size) || size < 1) {
			throw new RangeError('The worker pool size must be a positive integer.');
		}
		for(let i=0; i<size; i++) {
			const worker = createWorker();
			worker.onmessage = (ev) => this.onMessage(ev.data);
			worker.onerror = (ev) => {
				this.failWorker(i, new Error(`Web Worker #${i} failed: ${(ev && ev.message) || 'unknown error'}`));
			};
			worker.onmessageerror = () => {
				this.failWorker(i, new Error(`Web Worker #${i} sent a message that could not be deserialized.`));
			};
			this.workers.push(worker);
		}
	}

	/** The number of requests that have not been answered yet. */
	get pendingCount(): number {
		return this.pending.size;
	}

	/**
	 * Sends `message` (plus a generated `id`) to the worker `worker % size`.
	 * @returns the worker's final response.
	 */
	run(worker: number, message: WorkerResponse, transfer: Transferable[] = [], onProgress?: (data: WorkerResponse) => void): Promise<WorkerResponse> {
		if(this.terminated) {
			return Promise.reject(new Error('The worker pool has been terminated.'));
		}
		const index = worker % this.size;
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

	private onMessage(data: WorkerResponse): void {
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
			p.resolve(data);
		}
	}

	private failWorker(worker: number, err: Error): void {
		for(const [id, p] of this.pending) {
			if(p.worker !== worker) continue;
			this.pending.delete(id);
			p.reject(err);
		}
	}

}

