#!/bin/bash
openssl req -x509 -nodes -days 3650 \
    -newkey rsa:2048 -keyout server-key.pem \
    -out server-cert.pem -config server.cnf

openssl req -x509 -nodes -days 3650 \
    -newkey rsa:2048 -keyout client-key.pem \
    -out client-cert.pem -config client.cnf
