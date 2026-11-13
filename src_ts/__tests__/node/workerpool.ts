
import { WorkerPool, WorkerLike, WorkerResponse } from '../../workerpool';

/* eslint-disable @typescript-eslint/no-explicit-any */

// An in-process stand-in for a Web Worker: records the messages it receives and lets the test reply.
class FakeWorker implements WorkerLike {
	received: any[] = [];
	terminated = false;
	onmessage: ((ev: MessageEvent) => any) | null = null;
	onerror: ((ev: ErrorEvent) => any) | null = null;
	onmessageerror: ((ev: MessageEvent) => any) | null = null;
	postMessage(message: any): void {
		this.received.push(message);
	}
	terminate(): void {
		this.terminated = true;
	}
	reply(data: WorkerResponse): void {
		this.onmessage!({ data } as MessageEvent);
	}
	fail(message: string): void {
		this.onerror!({ message } as ErrorEvent);
	}
}

const createPool = (size: number, maxRestarts?: number) => {
	const workers: FakeWorker[] = [];
	const pool = new WorkerPool(size, () => {
		const w = new FakeWorker();
		workers.push(w);
		return w;
	}, { maxRestarts });
	return { pool, workers };
};

// Resolves to 'resolved' / 'rejected', or 'pending' if the promise has not settled after `ms`.
const settled = (p: Promise<unknown>, ms = 100): Promise<string> => Promise.race([
	p.then(() => 'resolved', () => 'rejected'),
	new Promise<string>((r) => setTimeout(() => r('pending'), ms)),
]);

describe('WorkerPool', () => {

	it('rejects a non-positive or non-integer size', () => {
		for(const size of [0, -1, 1.5, NaN]) {
			expect(() => new WorkerPool(size, () => new FakeWorker())).toThrow(RangeError);
		}
	});

	it('creates exactly `size` workers and sends each request to `worker % size`', () => {
		const { pool, workers } = createPool(3);
		expect(workers).toHaveLength(3);
		pool.run(0, { method: 'a' });
		pool.run(4, { method: 'b' });
		expect(workers[0].received.map((m) => m.method)).toEqual(['a']);
		expect(workers[1].received.map((m) => m.method)).toEqual(['b']);
		expect(workers[2].received).toHaveLength(0);
	});

	it('matches responses to requests by id, even out of order on the same worker', async () => {
		const { pool, workers } = createPool(1);
		const p1 = pool.run(0, { method: 'first' });
		const p2 = pool.run(0, { method: 'second' });
		const [m1, m2] = workers[0].received;
		expect(m1.id).not.toBe(m2.id);
		workers[0].reply({ id: m2.id, value: 2 });
		workers[0].reply({ id: m1.id, value: 1 });
		await expect(p1).resolves.toMatchObject({ value: 1 });
		await expect(p2).resolves.toMatchObject({ value: 2 });
		expect(pool.pendingCount).toBe(0);
	});

	it('passes progress messages to the callback before resolving', async () => {
		const { pool, workers } = createPool(1);
		const progress: number[] = [];
		const p = pool.run(0, { method: 'long' }, [], (data) => progress.push(data.n));
		const id = workers[0].received[0].id;
		workers[0].reply({ id, progress: true, n: 1 });
		workers[0].reply({ id, progress: true, n: 2 });
		workers[0].reply({ id, done: true });
		await expect(p).resolves.toMatchObject({ done: true });
		expect(progress).toEqual([1, 2]);
	});

	it('rejects a request when the worker answers with an error', async () => {
		const { pool, workers } = createPool(1);
		const p = pool.run(0, { method: 'bad' });
		workers[0].reply({ id: workers[0].received[0].id, error: 'Unknown method: bad' });
		await expect(p).rejects.toThrow('Unknown method: bad');
	});

	it('rejects the pending requests of a failed worker only (no hang)', async () => {
		const { pool, workers } = createPool(2);
		const onFailed = pool.run(0, { method: 'x' });
		const onOther = pool.run(1, { method: 'y' });
		workers[0].fail('WebAssembly.instantiate(): Out of memory');
		await expect(onFailed).rejects.toThrow(/Web Worker #0 failed: .*Out of memory/);
		expect(pool.pendingCount).toBe(1);
		workers[1].reply({ id: workers[1].received[0].id, ok: true });
		await expect(onOther).resolves.toMatchObject({ ok: true });
	});

	it('rejects the request when postMessage throws', async () => {
		const { pool, workers } = createPool(1);
		workers[0].postMessage = () => { throw new Error('DataCloneError'); };
		await expect(pool.run(0, { method: 'x' })).rejects.toThrow('DataCloneError');
		expect(pool.pendingCount).toBe(0);
	});

	it('terminate() stops the workers and rejects pending and later requests', async () => {
		const { pool, workers } = createPool(2);
		const p = pool.run(0, { method: 'x' });
		pool.terminate();
		expect(workers.every((w) => w.terminated)).toBe(true);
		await expect(p).rejects.toThrow('terminated');
		await expect(pool.run(1, { method: 'y' })).rejects.toThrow('terminated');
	});

	it('rejects an invalid maxRestarts', () => {
		for(const maxRestarts of [-1, 0.5, NaN]) {
			expect(() => new WorkerPool(1, () => new FakeWorker(), { maxRestarts })).toThrow(RangeError);
		}
	});
	
	// #32: a request routed to a worker that already failed must settle.
	it('rejects requests to a failed slot at once when restarts are disabled (#32)', async () => {
		const { pool, workers } = createPool(1, 0);
		const first = pool.run(0, { method: 'x' });
		workers[0].fail('WebAssembly.instantiate(): Out of memory');
		await expect(first).rejects.toThrow('Out of memory');
		expect(workers[0].terminated).toBe(true);
		expect(workers).toHaveLength(1);
		expect(pool.availableCount).toBe(0);
		const second = pool.run(0, { method: 'x' });
		expect(await settled(second)).toBe('rejected');
		const err = await second.catch((e) => e);
		expect(err.message).toMatch(/Web Worker #0 is unavailable: .*Out of memory/);
		expect(err.cause).toBeInstanceOf(Error);
		expect(err.cause.message).toMatch(/Out of memory/);
		// Nothing was posted to the dead worker.
		expect(workers[0].received).toHaveLength(1);
	});
	
	it('replaces a failed worker, and later requests go to the replacement', async () => {
		const { pool, workers } = createPool(1);
		const first = pool.run(0, { method: 'x' });
		workers[0].fail('crashed');
		await expect(first).rejects.toThrow('crashed');
		expect(workers).toHaveLength(2);
		expect(workers[0].terminated).toBe(true);
		const second = pool.run(0, { method: 'y' });
		expect(workers[1].received.map((m) => m.method)).toEqual(['y']);
		workers[1].reply({ id: workers[1].received[0].id, ok: true });
		await expect(second).resolves.toMatchObject({ ok: true });
		expect(pool.availableCount).toBe(1);
	});
	
	it('gives up after maxRestarts consecutive failures (no endless restart loop)', async () => {
		const { pool, workers } = createPool(1, 1);
		workers[0].fail('Out of memory');   // restart #1
		workers[1].fail('Out of memory');   // the replacement fails too: the slot is marked as failed
		expect(workers).toHaveLength(2);
		expect(workers.every((w) => w.terminated)).toBe(true);
		expect(pool.availableCount).toBe(0);
		expect(await settled(pool.run(0, { method: 'x' }))).toBe('rejected');
	});
	
	it('resets the restart count after a successful answer', async () => {
		const { pool, workers } = createPool(1, 1);
		workers[0].fail('crash 1');
		const p = pool.run(0, { method: 'x' });
		workers[1].reply({ id: workers[1].received[0].id, ok: true });
		await p;
		workers[1].fail('crash 2');         // allowed again: the slot had recovered
		expect(workers).toHaveLength(3);
		expect(pool.availableCount).toBe(1);
		workers[2].fail('crash 3');         // second failure in a row
		expect(workers).toHaveLength(3);
		expect(pool.availableCount).toBe(0);
	});
	
	it('ignores late errors from a worker that was already replaced', async () => {
		const { pool, workers } = createPool(1);
		workers[0].fail('crash');
		const p = pool.run(0, { method: 'x' });
		workers[0].fail('late duplicate error');
		expect(await settled(p)).toBe('pending');
		expect(workers).toHaveLength(2);
		workers[1].reply({ id: workers[1].received[0].id, ok: true });
		await expect(p).resolves.toMatchObject({ ok: true });
	});
	
	it('marks the slot as failed when the replacement cannot be created', async () => {
		let created = 0;
		const workers: FakeWorker[] = [];
		const pool = new WorkerPool(1, () => {
			if(created++ > 0) throw new Error('SecurityError');
			const w = new FakeWorker();
			workers.push(w);
			return w;
		});
		workers[0].fail('crash');
		await expect(pool.run(0, { method: 'x' })).rejects.toThrow(/unavailable: .*could not be restarted: SecurityError/);
	});
	
	it('does not restart a worker that only reported an error response', async () => {
		const { pool, workers } = createPool(1);
		const p = pool.run(0, { method: 'bad' });
		workers[0].reply({ id: workers[0].received[0].id, error: 'Unknown method: bad' });
		await expect(p).rejects.toThrow('Unknown method');
		expect(workers).toHaveLength(1);
		expect(workers[0].terminated).toBe(false);
	});
	
	it('lets callers that spread work over every worker fail fast', async () => {
		const { pool, workers } = createPool(2, 0);
		workers[0].fail('Out of memory');
		// Like decryptMany / mG generation: one request per worker, awaited with Promise.all.
		const all = Promise.all([0, 1].map((i) => pool.run(i, { method: 'x' })));
		expect(await settled(all)).toBe('rejected');
		await expect(all).rejects.toThrow('Out of memory');
	});
	
	it('ignores messages without a matching id', () => {
		const { pool, workers } = createPool(1);
		workers[0].reply({ id: 12345, value: 1 });
		workers[0].reply({ value: 1 });
		expect(pool.pendingCount).toBe(0);
	});

});

