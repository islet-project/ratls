# RaTls examples

* [client](./client) contains a simple RaTls client implementation
* [server](./server) contains a simple RaTls server implementation

## Run RaTls server
```sh
cd server
cargo run -- -c cert/server.crt -k cert/server.key -p keys/pkey.jwk
```

## Run RaTls client 
```sh
cd client
cargo run -- -r root-ca.crt -t token.bin
```

__WARNING__: The examples might not work due to [challenge verification](https://github.com/islet-project/ratls/blob/main/ratls/src/cert_verifier.rs#L130).
