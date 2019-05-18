#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

openssl genrsa -out "$DIR/../config_files/ca-key.pem" 2048

openssl req -x509 -new -nodes \
     -key "$DIR/../config_files/ca-key.pem" -sha256 \
     -days 1825 -out "$DIR/../config_files/ca-cert.pem" \
     -config "$DIR/../config_files/ca.cnf"

openssl req -x509 -nodes -days 3650 \
    -newkey rsa:2048 -keyout "$DIR/../config_files/server-key.pem" \
    -out "$DIR/../config_files/server-cert.pem" -config "$DIR/../config_files/server.cnf"

openssl req -new -sha256 -key "$DIR/../config_files/server-key.pem" \
    -out "$DIR/../config_files/server-cert.csr" -config "$DIR/../config_files/server.cnf"

openssl req -x509 -nodes -days 3650 \
    -newkey rsa:2048 -keyout "$DIR/../config_files/client-key.pem" \
    -out "$DIR/../config_files/client-cert.pem" -config "$DIR/../config_files/client.cnf"
