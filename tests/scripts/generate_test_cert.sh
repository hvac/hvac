#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

openssl req -x509 -nodes -days 3650 \
    -newkey rsa:2048 -keyout "$DIR/../config_files/server-key.pem" \
    -out "$DIR/../config_files/server-cert.pem" -config "$DIR/../config_files/server.cnf"

openssl req -x509 -nodes -days 3650 \
    -newkey rsa:2048 -keyout "$DIR/../config_files/client-key.pem" \
    -out "$DIR/../config_files/client-cert.pem" -config "$DIR/../config_files/client.cnf"
