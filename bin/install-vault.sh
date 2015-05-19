#!/bin/bash
set -eux

VAULT_VERSION=0.1.2

cd /tmp

curl -sOL https://dl.bintray.com/mitchellh/vault/vault_${VAULT_VERSION}_linux_amd64.zip
unzip vault_${VAULT_VERSION}_linux_amd64.zip
sudo mv vault /usr/local/bin
