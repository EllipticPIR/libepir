/**
 * Run a benchmark of EC-ElGamal ciphertext encryption / decryption.
 */

import crypto from 'crypto';
import fs from 'fs/promises';

const epir_ = require('../build_em/src/epir.js');

const time = () => new Date().getTime();
const LOOP = (10 * 1000);

(async () => {
	
	const mG_path = (process.argv.length < 3 ? `${process.env['HOME']}/.EllipticPIR/mG.bin` : process.argv[2]);
	
	const epir = await epir_();
	
	// Generate messages to encrypt.
	console.log('Generatig messages to encrypt...');
	const msg = new Array(LOOP);
	for(let i=0; i<LOOP; i++) {
		msg[i] = Math.floor(Math.random() * (1 << 24));
	}
	
	// Create key pair.
	console.log('Generatig a key pair...');
	epir._epir_randombytes_init();
	const privkey = epir._malloc(32);
	epir._epir_create_privkey(privkey);
	const pubkey = epir._malloc(32);
	epir._epir_pubkey_from_privkey(pubkey, privkey);
	
	// Load mG.bin.
	console.log('Loading mG.bin...');
	const mG = epir._malloc(36 * (1 << 24));
	const beginLoad = time();
	const handle = await fs.open(mG_path, 'r');
	if(!handle) throw new Error('Failed to open mG.bin.');
	const { bytesRead } = await handle.read(epir.HEAPU8, mG, 36 * (1 << 24));
	let elemsRead = bytesRead / 36;
	console.log(`mG.bin loaded in ${time() - beginLoad}ms.`);
	if(elemsRead != (1 << 24)) {
		console.log("Failed to load mG.bin!");
		return;
	}
	
	const ciphers = epir._malloc(64 * LOOP);
	const random = epir._malloc(32 * LOOP);
	crypto.randomFillSync(epir.HEAPU8.slice(random, random + 32 * LOOP));
	const beginEncrypt = time();
	for(let i=0; i<LOOP; i++) {
		epir._epir_ecelgamal_encrypt_fast(ciphers + 64 * i, privkey, msg[i], 0, random + 32 * i);
	}
	console.log(`Ciphertext encrypted in ${time() - beginEncrypt}ms.`);
	
	const beginDecrypt = time();
	for(let i=0; i<LOOP; i++) {
		const decrypted = epir._epir_ecelgamal_decrypt(privkey, ciphers + 64 * i, mG, 1 << 24);
		if(decrypted != msg[i]) {
			console.log(`Decryption error occured! (msg=${msg[i]}, decrypted=${decrypted})`);
		}
	}
	console.log(`Ciphertext decrypted in ${time() - beginDecrypt}ms.`);
	
	epir._free(privkey);
	epir._free(pubkey);
	epir._free(mG);
	epir._free(ciphers);
	
})();

