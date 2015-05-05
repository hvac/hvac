#!/bin/bash
set -eux

mkdir bin

curl -OL https://dl.bintray.com/mitchellh/vault/vault_0.1.1_linux_amd64.zip
unzip vault_0.1.1_linux_amd64.zip -d bin

bin/vault server -dev &

while [ ! -f $HOME/.vault-token ]; do
  echo Waiting for Vault to start
  sleep 1
done
