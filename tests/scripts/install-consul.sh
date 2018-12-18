#!/bin/bash
set -eux

DEFAULT_CONSUL_VERSION=1.4.0
HVAC_CONSUL_VERSION=${1:-$DEFAULT_CONSUL_VERSION}

function install_consul_release() {
    mkdir -p $HOME/bin

    cd /tmp

    curl -sOL https://releases.hashicorp.com/consul/${HVAC_CONSUL_VERSION}/consul_${HVAC_CONSUL_VERSION}_linux_amd64.zip
    unzip consul_${HVAC_CONSUL_VERSION}_linux_amd64.zip
    mv consul $HOME/bin
}

install_consul_release
