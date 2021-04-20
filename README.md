Crypto Incognito client library
===============================

This library contains a client-side library accessing [Crypto Incognito](https://crypto-incognito.com/).

*Crypto Incognito* is a web service which **serves Bitcoin's UTXOs** (unspent transaction outputs) database.
The queries sent to our servers are just an array of EC-ElGamal ciphertext of which
we does not know the private key (nor the public key).
Hence, you can **query your address to the database without revealing your Bitcoin address**,
and of course your amount of bitcoins you hold.

This service can be used as a back-end server for a Bitcoin wallet or a blockexplorer
which consider the users' privacy most important.

Users who own a significant amount of bitcoins are highly encouraged to use Crypto Incognito for your privacy, safety and security.

Install
-------

```
# Install dependencies.
$ sudo apt install

# Clone the repository.
$ git clone https://github.com/crypto-incognito/ci-lib.git
$ cd ci-lib

# Checkout the third party repositories.
$ git submodule init && git submodule update --recursive

# Make the build directory.
$ mkdir build
$ cd build

# Configure using CMake.
$ cmake ../

# Build (change the number "4" to your physical CPU cores to parallelize the build).
$ make -j4
```

Usage
-----





