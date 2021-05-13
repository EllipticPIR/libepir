
import { epir_t } from './epir_t';

export let epir: epir_t<any>;
try {
	epir = require('./addon');
} catch(e) {
	epir = require('./wasm');
}

