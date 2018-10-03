#!/bin/bash
set -eux

DEFAULT_VAULT_VERSION=0.11.2
VAULT_VERSION=${1:-$DEFAULT_VAULT_VERSION}

function build_and_install_vault_head_ref() {
    mkdir -p $HOME/bin

    eval "$(GIMME_GO_VERSION=1.10.3 gimme)"

    export GOPATH=$HOME/go
    mkdir $GOPATH

    export PATH=$GOPATH/bin:$PATH

    go get github.com/tools/godep
    go get github.com/mitchellh/gox

    git clone https://github.com/hashicorp/vault.git $GOPATH/src/github.com/hashicorp/vault
    cd $GOPATH/src/github.com/hashicorp/vault
    make dev

    mv bin/vault $HOME/bin
}

function install_vault_release() {
    mkdir -p $HOME/bin

    cd /tmp

    curl -sOL https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip
    unzip vault_${VAULT_VERSION}_linux_amd64.zip
    mv vault $HOME/bin
}

if [[ "$(tr [A-Z] [a-z] <<<"$VAULT_VERSION")" == "head" ]]; then
    build_and_install_vault_head_ref
else
    install_vault_release
fi
