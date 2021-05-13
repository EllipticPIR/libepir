libepir - EllipticPIR client library
====================================

[![Coverage Status](https://coveralls.io/repos/github/EllipticPIR/libepir/badge.svg?branch=master)](https://coveralls.io/github/EllipticPIR/libepir?branch=master)

This library contains cryptographic functions which are required
to encrypt a query (a selector) to the EllipticPIR server
and to decrypt a reply from the EllipticPIR server.

This repository provides native C library and bindings for C++, JavaScript and TypeScript programming languages.

Install
-------

### For Ubuntu users (PPA)

If you are running Ubuntu, you can install a pre-built binary from the PPA repo.

```
$ sudo apt-add-repository ppa:visvirial/epir
$ sudo apt update
$ sudo apt install libepir-dev
```

### Build your own

To build and install *libepir*, you need to install [the customized version of *libsodium*](https://github.com/EllipticPIR/libsodium).

```
$ git clone https://github.com/EllipticPIR/libsodium.git
$ cd libsodium
$ ./configure
$ make -j4  # (change the number "4" to your physical CPU cores to parallelize the build).
$ sudo make install
```

Then, continue building *libepir*.

```
$ git clone https://github.com/EllipticPIR/libepir.git
$ cd libepir
$ mkdir build
$ cd build
$ cmake -DCMAKE_BUILD_TYPE=Release ../
$ make -j4  # (change the number "4" to your physical CPU cores to parallelize the build).
$ sudo make install
```

Generate mG.bin
---------------

To decrypt a server's reply, you need to generate the *mG.bin* file.
This file contains the pre-computation values of (G, 2\*G, .., (0xFFFFFF)\*G),
where G is the generater of the Ed25519 curve.

```
$ epir_genm
```

The computation may take tens of seconds to finish.
The computation time depends on the CPU power of your machine.
(For comparison, on my desktop (Intel Core i7-7700K) it takes about ~15sec.)

The generated file will be located in *$HOME/.EllipticPIR/mG.bin*.
The file size will be ~576MiB.

If you will not decrypt a server's reply, you can skip this step.

Usage
-----

### C

See [epir.h](./src/epir.h) for function definitions.

For general usage, see bench_\*.c files.

The C implementation has no runtime heap memory allocation.

### C++

See [epir.hpp](./src/epir.hpp) for class definitions.

For general usage, see bench_\*.cpp files.

### JavaScript / TypeScript

See [index.ts](./src/index.ts) for Node.js binding definitions.

For general usage, see [test_nap.ts](./src/test_napi.ts).



