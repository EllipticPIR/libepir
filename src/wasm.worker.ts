
const wasm_ = require('../dist/epir.js');

const CTX_SIZE = 124;
const MG_SIZE = 36;
const MG_P3_SIZE = 4 * 40;

const worker: Worker = self as any;

const store_uint32_t = (wasm: any , offset: number, n: number) => {
	for(let i=0; i<4; i++) {
		wasm.HEAPU8[offset + i] = n & 0xff;
		n >>= 8;
	}
}

interface KeyValue {
	[key: string]: Function;
}
const funcs: KeyValue = {
	mg_generate_prepare: async (params: { nThreads: number, mmax: number }) => {
		const wasm = await wasm_();
		const ctx_ = wasm._malloc(CTX_SIZE);
		store_uint32_t(wasm, ctx_, params.mmax);
		const mG_ = wasm._malloc(params.nThreads * MG_SIZE);
		const mG_p3_ = wasm._malloc(params.nThreads * MG_P3_SIZE);
		let pointsComputed = 0;
		const cb = wasm.addFunction((data: any) => {
			pointsComputed++;
			worker.postMessage({ method: 'mg_generate_cb', pointsComputed: pointsComputed });
		}, 'vi');
		wasm._epir_ecelgamal_mg_generate_prepare(ctx_, mG_, mG_p3_, params.nThreads, cb, null);
		wasm.removeFunction(cb);
		const ctx = new Uint8Array(wasm.HEAPU8.subarray(ctx_, ctx_ + 124));
		const mG = new Uint8Array(wasm.HEAPU8.subarray(mG_, mG_ + params.nThreads * MG_SIZE));
		const mG_p3 = new Uint8Array(wasm.HEAPU8.subarray(mG_p3_, mG_p3_ + params.nThreads * MG_P3_SIZE));
		worker.postMessage({
			method: 'mg_generate_prepare', ctx: ctx, mG: mG, mG_p3: mG_p3,
		}, [ctx.buffer, mG.buffer, mG_p3.buffer]);
		wasm._free(ctx_);
		wasm._free(mG_);
		wasm._free(mG_p3_);
	},
	mg_generate_compute: async (params: { nThreads: number, mmax: number, ctx: Uint8Array, mG_p3: Uint8Array, threadId: number }) => {
		const wasm = await wasm_();
		const mG_count = Math.ceil(params.mmax / params.nThreads) - 1;
		const ctx_ = wasm._malloc(CTX_SIZE);
		wasm.HEAPU8.set(params.ctx, ctx_);
		const mG_ = wasm._malloc(mG_count * MG_SIZE);
		const mG_p3_ = wasm._malloc(MG_P3_SIZE);
		wasm.HEAPU8.set(params.mG_p3, mG_p3_);
		let pointsComputed = params.nThreads;
		const cb = wasm.addFunction((data: any) => {
			pointsComputed++;
			worker.postMessage({ method: 'mg_generate_cb', pointsComputed: pointsComputed });
		}, 'vi');
		wasm._epir_ecelgamal_mg_generate_compute(ctx_, mG_, mG_count, mG_p3_, 0, 1, cb, null);
		wasm.removeFunction(cb);
		const mG = new Uint8Array(wasm.HEAPU8.subarray(mG_, mG_ + mG_count * MG_SIZE));
		worker.postMessage({
			method: 'mg_generate_compute', mG: mG,
		}, [mG.buffer]);
		wasm._free(ctx_);
		wasm._free(mG_);
		wasm._free(mG_p3_);
	},
};

worker.addEventListener('message', (ev) => {
	funcs[ev.data.method].call(null, ev.data);
});

