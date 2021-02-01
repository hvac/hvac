#!/bin/bash
set -eux

DEFAULT_CONSUL_VERSION="1.4.0"
DEFAULT_CONSUL_DIRECTORY="${HOME}/.local/bin"
HVAC_CONSUL_VERSION="${1:-$DEFAULT_CONSUL_VERSION}"
HVAC_CONSUL_DIRECTORY="${2:-$DEFAULT_CONSUL_DIRECTORY}"

function install_consul_release() {
    cd "/tmp"

    download_url="https://releases.hashicorp.com/consul/${HVAC_CONSUL_VERSION}/consul_${HVAC_CONSUL_VERSION}_linux_amd64.zip"
    download_file="consul_${HVAC_CONSUL_VERSION}.zip"
    curl -sL "${download_url}" -o "${download_file}"
    unzip "${download_file}"

    mkdir -p "${HVAC_CONSUL_DIRECTORY}"
    mv "consul" "${HVAC_CONSUL_DIRECTORY}"
}

install_consul_release
