# MiniPQC - A minimal Cosmos SDK chain with PQC

This repository contains an example of a tiny, but working Cosmos SDK chain utilizing post-quantum cryptography and digital signatures.
It uses the least modules possible and is intended to be used as a starting point for building your own chain, without all the boilerplate that other tools generate.

### Prerequisites

* Install Go as described [here](https://go.dev/doc/install).
* Add `GOPATH` to your `PATH`:
  * `export PATH="$PATH:/usr/local/go/bin:$(/usr/local/go/bin/go env GOPATH)/bin"`

You are all set!

### Installation

Install and run:

```sh
git clone git@github.com:Yug-Shah/pqc-cosmos-minimal.git
cd pqc-cosmos-minimal
make install # install the binary
make init # initialize the chain
```
<!-- minid start # start the chain -->

### Troubleshoot

After running `make install`, verify `minid` has been installed by doing `which minid`.
If `minid` is not found, verify that your `$PATH` is configured correctly.

## Useful links

* [Cosmos-SDK Documentation](https://docs.cosmos.network/)
* [liboqs-go](https://github.com/open-quantum-safe/liboqs-go)
