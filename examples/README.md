# RaTls examples

* [client](./client) contains a simple RaTls client implementation
* [server](./server) contains a simple RaTls server implementation

## Run RaTls server
```sh
cd server
cargo run -- -c cert/server.crt -k cert/server.key
```

## Run RaTls client on ARM CCA realm
```sh
date 120512002023  # make sure to have somewhat modern date on the realm
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
a `disable_challenge` feature:

```
cargo run --feature disable_challenge -- -c cert/server.crt -k cert/server.key
```
