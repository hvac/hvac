#!/bin/bash
set -eux

curl -OL https://dl.bintray.com/mitchellh/vault/vault_0.1.1_linux_amd64.zip
unzip vault_0.1.1_linux_amd64.zip
mv vault /usr/local/bin/vault

vault server -dev &

while [ ! -f $HOME/.vault-token ]; do
  echo Waiting for Vault to start
  sleep 1
done
