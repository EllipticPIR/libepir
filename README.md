libepir - EllipticPIR client library
====================================

![CMake](https://github.com/EllipticPIR/libepir/actions/workflows/cmake.yml/badge.svg)
![Node.js CI](https://github.com/EllipticPIR/libepir/actions/workflows/node.js.yml/badge.svg)
[![codecov](https://codecov.io/gh/EllipticPIR/libepir/branch/master/graph/badge.svg?token=SUZFQ09J2O)](https://codecov.io/gh/EllipticPIR/libepir)

EllipticPIR is a private information retrieval (PIR) implementation backed by the EC-ElGamal encryption.

Try online WebAssembly demo: https://demo.ellipticpir.com/

This library contains cryptographic functions which are required
to encrypt a query (a selector) to the EllipticPIR server
and to decrypt a reply from the EllipticPIR server.

This repository provides native C library and bindings for C++, JavaScript and TypeScript programming languages.

C / C++
-------

The C implementation has no runtime heap memory allocation.
The C++ bindings is a header-only library.

### Install

```bash
$ git clone https://github.com/EllipticPIR/libepir.git
$ cd libepir
$ mkdir build_c
$ cd build_c
$ cmake -DCMAKE_BUILD_TYPE=Release ..
$ make -j4  # (change the number "4" to your physical CPU cores to parallelize the build).
$ sudo make install
```

### Generate mG.bin

```bash
$ epir_genm
```

### Usage

Include [epir.h](./src_c/epir.h) (C) or [epir.hpp](./src_c/epir.hpp) (C++) in your source code.

For general usage, see [./src\_c/bench\_\*.(c|cpp)](./src_c) files.

Node.js / TypeScript
--------------------

This library both includes Node.js native addons (faster, no browser support) and
WebAssembly builds (slower, browser support).

### Install

#### npm

```bash
$ npm install epir
```

#### Build your own

```bash
$ git clone https://github.com/EllipticPIR/libepir.git
$ cd libepir
$ npm ci
```

### Usage

See [./src\_ts/types.ts](./src_ts/types.ts) for Node.js binding definitions.

For general usage, see files under the [./src\_ts/\_\_tests\_\_](./src_ts/__tests__) directory and
[./pages/index.vue](./pages/index.vue).

FAQs
----

### What is mG.bin?

To decrypt a server's reply, you need to generate the *mG.bin* file.
This file contains the pre-computation values of (G, 2\*G, .., (0xFFFFFF)\*G),
where G is the generater of the Ed25519 curve.

To generate mG.bin, run

```bash
$ epir_genm
```

or

```bash
$ npm run epir_genm
```

The computation may take tens of seconds to finish.
The computation time depends on the CPU power of your machine.
(For comparison, on my desktop (Intel Core i7-7700K) it takes about ~15sec.)

The generated file will be located in *$HOME/.EllipticPIR/mG.bin*.
The file size will be ~576MiB.

If you will not decrypt a server's reply, you can skip this step.

