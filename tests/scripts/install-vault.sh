#!/bin/bash
set -eux

DEFAULT_VAULT_VERSION=1.1.3
HVAC_VAULT_VERSION=${1:-$DEFAULT_VAULT_VERSION}

function build_and_install_vault_head_ref() {
    mkdir -p $HOME/bin

    eval "$(GIMME_GO_VERSION=1.11 gimme)"

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

    #curl -sOL https://releases.hashicorp.com/vault/${HVAC_VAULT_VERSION}/vault_${HVAC_VAULT_VERSION}_linux_amd64.zip
    #unzip vault_${HVAC_VAULT_VERSION}_linux_amd64.zip
    curl -sOL https://s3-us-west-2.amazonaws.com/hc-enterprise-binaries/vault/ent/${HVAC_VAULT_VERSION}/vault-enterprise_${HVAC_VAULT_VERSION}%2Bent_linux_amd64.zip
    unzip vault-enterprise_${HVAC_VAULT_VERSION}%2Bent_linux_amd64.zip

    mv vault $HOME/bin
}

if [[ "$(tr [A-Z] [a-z] <<<"$HVAC_VAULT_VERSION")" == "head" ]]; then
    build_and_install_vault_head_ref
else
    install_vault_release
fi
