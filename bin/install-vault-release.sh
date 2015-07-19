#!/bin/bash
set -eux

VAULT_VERSION=0.2.0

mkdir -p $HOME/bin

cd /tmp

curl -sOL https://dl.bintray.com/mitchellh/vault/vault_${VAULT_VERSION}_linux_amd64.zip
unzip vault_${VAULT_VERSION}_linux_amd64.zip
mv vault $HOME/bin
