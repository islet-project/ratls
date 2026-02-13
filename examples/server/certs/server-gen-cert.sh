#!/bin/sh

# This will only regenerate server.crt, but can be used to change accepted IPs in server.cnf

openssl x509 -req -in server.csr -CA root-ca.crt -CAkey root-ca.key -out server.crt -days 3650 -sha256 -extfile server.cnf -extensions server
