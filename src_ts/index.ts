
eport let epir;
try {
	epir = require('./addon');
} catch(e) {
	epir = require('./wasm');
}

