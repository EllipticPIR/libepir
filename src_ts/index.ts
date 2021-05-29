
import { EpirCreateFunction, DecryptionContextCreateFunction } from './types';

let epir: any;
try {
	epir = require('./addon');
} catch(e) {
	epir = require('./wasm');
}

export const createEpir: EpirCreateFunction = epir.createEpir;
export const createDecryptionContext: DecryptionContextCreateFunction = epir.createDecryptionContext;

