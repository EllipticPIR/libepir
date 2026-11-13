
import { arrayBufferConcat, getRandomScalarsConcat } from './util';
import { SelectorFactoryBase, DEFAULT_CAPACITIES, CIPHER_SIZE } from './types';
import { WorkerPool, resolveWorkerPool } from './wasm.workers';

export class SelectorFactory implements SelectorFactoryBase {

	readonly pool: WorkerPool;
	ciphers: ArrayBuffer[][] = [[], []];

	/**
	 * @param workers The worker pool to use, or a worker count to create a dedicated pool.
	 *                Defaults to the pool shared with Epir and DecryptionContext.
	 */
	constructor(
		public readonly isFast: boolean, public readonly key: ArrayBuffer,
		/* istanbul ignore next */
		public readonly capacities: number[] = DEFAULT_CAPACITIES,
		workers?: WorkerPool | number) {
		this.pool = resolveWorkerPool(workers);
	}

	async fill(): Promise<void> {
		const nWorkers = this.pool.size;
		const promises = this.capacities.map((capacity, msg) => {
			const needs = capacity - this.ciphers[msg].length;
			const ciphersPerWorker = Math.floor(needs / nWorkers);
			const tasks: Promise<void>[] = [];
			for(let workerId=0; workerId<nWorkers; workerId++) {
				const nCiphers = (workerId == nWorkers - 1 ?
					needs - (nWorkers - 1) * ciphersPerWorker : ciphersPerWorker);
				if(nCiphers <= 0) continue;
				const random = getRandomScalarsConcat(nCiphers);
				tasks.push(this.pool.run(workerId, {
					method: 'selector_factory_fill', isFast: this.isFast, key: this.key, msg: msg, count: nCiphers, random: random,
				}, [random]).then((res) => {
					const ciphers: ArrayBuffer = res.ciphers;
					for(let i=0; i*CIPHER_SIZE<ciphers.byteLength; i++) {
						this.ciphers[msg].push(ciphers.slice(i * CIPHER_SIZE, (i + 1) * CIPHER_SIZE));
					}
				}));
			}
			return Promise.all(tasks);
		});
		await Promise.all(promises);
	}

	create(indexCounts: number[], idx: number, refill = true): ArrayBuffer {
		let prod = indexCounts.reduce((acc, v) => acc * v, 1);
		const ret: ArrayBuffer[] = [];
		for(let ic=0; ic<indexCounts.length; ic++) {
			const cols = indexCounts[ic];
			prod /= cols;
			const rows = Math.floor(idx / prod);
			idx -= rows * prod;
			for(let r=0; r<cols; r++) {
				const msg = (r == rows ? 1 : 0);
				const cipher = this.ciphers[msg].pop();
				if(!cipher) throw new Error('Insufficient ciphers cache.');
				ret.push(cipher);
			}
		}
		const concat = arrayBufferConcat(ret);
		if(refill) {
			this.fill().catch((e) => console.error('SelectorFactory: failed to refill the cache:', e));
		}
		return concat;
	}

}

