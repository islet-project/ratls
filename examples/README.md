# RaTls examples

* [client](./client) contains a simple RaTls client implementation
* [server](./server) contains a simple RaTls server implementation

To increase verbosity prepend the commands with `RUST_LOG=debug`

## Run RaTls server
```sh
cd server
cargo run -- -c cert/server.crt -k cert/server.key
```

## Run RaTls client on ARM CCA realm
```sh
date 012812002026  # make sure to have a date within certificate validity scope
cd client
cargo run -- -r root-ca.crt -u SERVER_IP:1337
```

## Run RaTls client on X64 test host
```sh
cd client
cargo run -- -r root-ca.crt -t token.bin
```

__WARNING__: The X64 test host will not work fully due to [challenge
verification](https://github.com/islet-project/ratls/blob/main/ratls/src/cert_verifier.rs#L130). If
you need the test to pass disable the challenge verification on the server with
a `disable-challenge` feature:

```
cargo run --features disable-challenge -- -c cert/server.crt -k cert/server.key
```
