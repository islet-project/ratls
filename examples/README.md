# RaTls examples

* [client](./client) contains a simple RaTls client implementation
* [server](./server) contains a simple RaTls server implementation

To increase verbosity prepend the commands with `RUST_LOG=debug`

## Run RaTls server
```sh
cd server
cargo run -- -c certs/server.crt -k certs/server.key
```

## Run RaTls client on ARM CCA realm
```sh
date -s "2026-02-13 18:00"  # make sure to have a date within certificate validity scope
cd client
cargo run -- -r certs/root-ca.crt -u SERVER_IP:1337
```

## Run RaTls client on X64 test host
```sh
cd client
cargo run -- -r certs/root-ca.crt -t ratls/token.bin
```

__WARNING__: The X64 test host will not work fully due to [challenge
verification](https://github.com/islet-project/ratls/blob/main/ratls/src/cert_verifier.rs#L130). If
you need the test to pass disable the challenge verification on the server with
a `disable-challenge` feature:

```
cargo run --features disable-challenge -- -c certs/server.crt -k certs/server.key
```

## Optional features, token verification

By default the server/ratls checks only for the challenge (unless disabled as
shown above). To fully utilize RA-TLS protocol one can add two additional
features that verify the tokens' content/values (platform and realm tokens).

```
cargo run --features realm,veraison -- -c certs/server.crt -k certs/server.key -p ratls/pkey.jwk -j ratls/example.json
```

For this to work though additional steps need to be taken. Veraison service
needs to be running and be properly provisioned. The `reference.json` file needs
to be prepared and properly filled as well. The details are out of scope of
this readme, but the main thing is that the server with those two features can
fully test the RA-TLS workflow. For more details see here:

https://github.com/islet-project/islet/blob/main/examples/veraison/RUN.md
