
import { epir_t } from './epir_t';

export let createEpir: () => Promise<epir_t<any>>;
try {
	createEpir = require('./addon').createEpir;
} catch(e) {
	createEpir = require('./wasm').createEpir;
}

