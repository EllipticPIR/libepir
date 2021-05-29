
import { arrayBufferConcat, getRandomScalarsConcat } from './util';
import { SelectorFactoryBase, DEFAULT_CAPACITIES, CIPHER_SIZE } from './EpirBase';
import SelectorFactoryWorker from './wasm.SelectorFactory.worker.ts';

export class SelectorFactory implements SelectorFactoryBase {
	
	workers: SelectorFactoryWorker[][] = [[], []];
	ciphers: ArrayBuffer[][] = [[], []];
	
	constructor(
		public readonly isFast: boolean, public readonly key: ArrayBuffer,
		public readonly capacities: number[] = DEFAULT_CAPACITIES, nThreads = navigator.hardwareConcurrency) {
		for(let i=0; i<nThreads; i++) {
			this.workers[0][i] = new SelectorFactoryWorker();
			this.workers[1][i] = new SelectorFactoryWorker();
		}
	}
	
	async fill(): Promise<void> {
		const promises = this.capacities.map((capacity, msg) => {
			const needs = capacity - this.ciphers[msg].length;
			const ciphersPerWorker = Math.floor(needs / this.workers[msg].length);
			return Promise.all(this.workers[msg].map((worker, workerId) => {
				const nCiphers = (workerId == this.workers[msg].length - 1 ?
					needs - (this.workers[msg].length - 1) * ciphersPerWorker : ciphersPerWorker);
				return new Promise<void>((resolve) => {
					if(nCiphers <= 0) {
						resolve();
						return;
					}
					worker.onmessage = (ev) => {
						switch(ev.data.method) {
							case 'generateCiphers':
								for(let i=0; i*CIPHER_SIZE<ev.data.ciphers.byteLength; i++) {
									this.ciphers[ev.data.msg].push(ev.data.ciphers.slice(i * CIPHER_SIZE, (i + 1) * CIPHER_SIZE));
								}
								resolve();
								break;
						}
					};
					const random = getRandomScalarsConcat(nCiphers);
					worker.postMessage({
						method: 'generateCiphers',
						params: { isFast: this.isFast, key: this.key, msg: msg, count: nCiphers, random: random },
					}, [random]);
				});
			}));
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
		if(refill) this.fill();
		return concat;
	}
	
}

