#!/bin/bash
openssl genrsa 4096 > server.key
openssl req -new -sha256 -key server.key -out server.csr -subj "/O=Vault testing/CN=server.example.com"
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server-self-signed.crt
