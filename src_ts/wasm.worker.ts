
/**
 * Web Worker for the browser (WASM) build. Used through WorkerPool (see workerpool.ts / wasm.workers.ts):
 * every request carries an `id`, which is echoed in every message posted back.
 */

import { MG_SIZE, SCALAR_SIZE, CIPHER_SIZE } from './types';
import { createLibEpirHelper, LibEpirHelper } from './wasm.libepir';
import { arrayBufferConcat } from './util';

const worker: Worker = self as unknown as Worker;

// One Emscripten module instance per worker, created on the first request and reused afterwards.
// (Creating one per message allocated a new WebAssembly memory for every request.)
let helperPromise: Promise<LibEpirHelper> | null = null;
const getHelper = (): Promise<LibEpirHelper> => {
	if(!helperPromise) helperPromise = createLibEpirHelper();
	return helperPromise;
};

type Result = { data: { [key: string]: unknown }, transfer: Transferable[] };
type Progress = (data: { [key: string]: unknown }) => void;

// For mG.bin generation.
const mGGenerateCompute = (
	helper: LibEpirHelper,
	params: { nThreads: number, mmax: number, ctx: ArrayBuffer, mG_p3: ArrayBuffer, threadId: number, cbInterval: number },
	progress: Progress): Result => {
	const mG_count = Math.ceil(params.mmax / params.nThreads) - 1;
	const ctx_ = helper.malloc(params.ctx);
	const mG_ = helper.malloc(mG_count * MG_SIZE);
	const mG_p3_ = helper.malloc(params.mG_p3);
	let pointsComputed = 0;
	const cb = helper.addFunction(() => {
		pointsComputed++;
		if(pointsComputed % params.cbInterval == 0 || pointsComputed === mG_count) {
			progress({ pointsComputed: pointsComputed });
		}
	}, 'vi');
	// Run.
	helper.call('mG_generate_compute',
		ctx_, mG_, mG_count, mG_p3_, params.nThreads + params.threadId, params.nThreads, cb, null);
	helper.removeFunction(cb);
	// Sort.
	helper.call('mG_sort', mG_, mG_count);
	const mG = helper.slice(mG_, mG_count * MG_SIZE);
	helper.free(ctx_);
	helper.free(mG_);
	helper.free(mG_p3_);
	return { data: { mG: mG }, transfer: [mG] };
};

// For selector creation.
const selectorCreate = (
	helper: LibEpirHelper,
	params: { choices: ArrayBuffer, key: ArrayBuffer, random: ArrayBuffer, isFast: boolean }): Result => {
	const key_ = helper.malloc(params.key);
	const cipher_ = helper.malloc(CIPHER_SIZE);
	const random_ = helper.malloc(SCALAR_SIZE);
	const encryptFn = (params.isFast ? 'ecelgamal_encrypt_fast' : 'ecelgamal_encrypt');
	const choicesView = new Uint8Array(params.choices);
	const selector: ArrayBuffer[] = [];
	for(let i=0; i<params.choices.byteLength; i++) {
		helper.set(params.random, i * SCALAR_SIZE, SCALAR_SIZE, random_);
		helper.call(encryptFn, cipher_, key_, choicesView[i], 0, random_);
		selector.push(helper.slice(cipher_, CIPHER_SIZE));
	}
	helper.free(key_);
	helper.free(cipher_);
	helper.free(random_);
	const selectorConcat = arrayBufferConcat(selector);
	return { data: { selector: selectorConcat }, transfer: [selectorConcat] };
};

// For SelectorFactory: encrypt `count` copies of `msg`.
const selectorFactoryFill = (
	helper: LibEpirHelper,
	params: { isFast: boolean, key: ArrayBuffer, msg: number, count: number, random: ArrayBuffer }): Result => {
	const ciphers: ArrayBuffer[] = [];
	const cipher_ = helper.malloc(CIPHER_SIZE);
	const key_ = helper.malloc(params.key);
	const r_ = helper.malloc(SCALAR_SIZE);
	const encryptFn = (params.isFast ? 'ecelgamal_encrypt_fast' : 'ecelgamal_encrypt');
	for(let i=0; i<params.count; i++) {
		helper.set(params.random, i * SCALAR_SIZE, SCALAR_SIZE, r_);
		helper.call(encryptFn, cipher_, key_, params.msg&0xffffffff, Math.floor(params.msg/0x100000000), r_);
		ciphers.push(helper.slice(cipher_, CIPHER_SIZE));
	}
	helper.free(cipher_);
	helper.free(key_);
	helper.free(r_);
	const ciphersConcat = arrayBufferConcat(ciphers);
	return { data: { ciphers: ciphersConcat }, transfer: [ciphersConcat] };
};

// For reply decryption.
const decryptMGMany = (
	helper: LibEpirHelper,
	params: { ciphers: ArrayBuffer, privkey: ArrayBuffer }): Result => {
	const privkey_ = helper.malloc(params.privkey);
	const cipher_ = helper.malloc(CIPHER_SIZE);
	const mG = new Uint8Array(32 * (params.ciphers.byteLength / CIPHER_SIZE));
	for(let i=0; CIPHER_SIZE*i<params.ciphers.byteLength; i++) {
		helper.set(params.ciphers, i * CIPHER_SIZE, CIPHER_SIZE, cipher_);
		helper.call('ecelgamal_decrypt_to_mG', privkey_, cipher_);
		mG.set(helper.subarray(cipher_, 32), i * 32);
	}
	helper.free(privkey_);
	helper.free(cipher_);
	return { data: { mG: mG.buffer }, transfer: [mG.buffer] };
};

worker.onmessage = async (ev) => {
	const id = ev.data.id;
	try {
		const helper = await getHelper();
		const progress: Progress = (data) => worker.postMessage({ ...data, id: id, progress: true });
		let result: Result;
		switch(ev.data.method) {
			case 'mg_generate_compute':
				result = mGGenerateCompute(helper, ev.data, progress);
				break;
			case 'selector_create':
				result = selectorCreate(helper, ev.data);
				break;
			case 'selector_factory_fill':
				result = selectorFactoryFill(helper, ev.data);
				break;
			case 'decrypt_mG_many':
				result = decryptMGMany(helper, ev.data);
				break;
			default:
				throw new Error(`Unknown method: ${ev.data.method}`);
		}
		worker.postMessage({ ...result.data, id: id }, result.transfer);
	} catch(e) {
		worker.postMessage({ id: id, error: (e instanceof Error ? e.message : String(e)) });
	}
};

