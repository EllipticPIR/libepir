
import { arrayBufferConcat } from './util';
import { EpirBase } from './EpirBase';
import SelectorFactoryWorker from './SelectorFactory.worker.ts';

export class SelectorFactory {
	
	ciphers: ArrayBuffer[][] = [[], []];
	running: boolean = false;
	stopped: boolean = false;
	workers: SelectorFactoryWorker[][] = [[], []];
	
	constructor(
		public epir: EpirBase,
		public capacities = [10000, 100],
		nThreads = navigator.hardwareConcurrency, public interval: number = 100) {
		for(let i=0; i<nThreads; i++) {
			this.workers[0][i] = new SelectorFactoryWorker();
			this.workers[1][i] = new SelectorFactoryWorker();
		}
	}
	
	private async mainLoop(isFast: boolean, key: ArrayBuffer) {
		if(!this.running) {
			this.stopped = true;
			return;
		}
		const promises = this.capacities.map((capacity, msg) => {
			const needs = capacity - this.ciphers[msg].length;
			const ciphersPerWorker = Math.ceil(needs / this.workers[msg].length);
			return Promise.all(this.workers[msg].map((worker, workerId) => {
				const nCiphers = (workerId == this.workers[msg].length - 1 ?
					needs - (this.workers[msg].length - 1) * ciphersPerWorker : ciphersPerWorker);
				return new Promise<void>((resolve, reject) => {
					worker.onmessage = (ev) => {
						switch(ev.data.method) {
							case 'cipher':
								this.ciphers[ev.data.msg].push(ev.data.cipher);
								break;
							case 'generateCiphers':
								resolve();
								break;
						}
					};
					worker.postMessage({
						method: 'generateCiphers',
						params: [this.epir, isFast, key, msg, nCiphers],
					});
				});
			}));
		});
		await Promise.all(promises);
		setTimeout(() => { this.mainLoop(isFast, key) }, this.interval);
	}
	
	start(pubkey: ArrayBuffer) {
		this.running = true;
		return this.mainLoop(false, pubkey);
	}
	
	startFast(privkey: ArrayBuffer) {
		this.running = true;
		return this.mainLoop(true, privkey);
	}
	
	stop() {
		this.stopped = false;
		this.running = false;
		return new Promise<void>((resolve, reject) => {
			const checkStopped = () => {
				if(this.stopped) {
					resolve();
				} else {
					setTimeout(checkStopped, 10);
				}
			}
			checkStopped();
		});
	}
	
	create(indexCounts: number[], idx: number): ArrayBuffer {
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
				if(!cipher) throw new Error('Insufficient ciphers buffer.');
				ret.push(cipher);
			}
		}
		return arrayBufferConcat(ret);
	}
	
}

