#!/bin/bash
set -eux

go get github.com/tools/godep
go get github.com/mitchellh/gox

git clone https://github.com/hashicorp/vault.git $GOPATH/src/github.com/hashicorp/vault
cd $GOPATH/src/github.com/hashicorp/vault
make dev

sudo mv bin/vault /usr/local/bin
