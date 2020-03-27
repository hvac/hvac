#!/bin/bash
set -eux

DEFAULT_VAULT_VERSION="1.3.4"
DEFAULT_VAULT_LICENSE="oss"
DEFAULT_VAULT_DIRECTORY="${HOME}/bin"
HVAC_VAULT_VERSION="${1:-$DEFAULT_VAULT_VERSION}"
HVAC_VAULT_LICENSE="${2:-$DEFAULT_VAULT_LICENSE}"
HVAC_VAULT_DIRECTORY="${3:-$DEFAULT_VAULT_DIRECTORY}"

function build_and_install_vault_ref() {
    if command -v gimme &>"/dev/null"; then
        eval "$(GIMME_GO_VERSION=1.12.7 gimme)"
    fi
    export PATH="$(go env GOPATH)/bin:${PATH}"

    build_dir="/tmp/src/github.com/hashicorp/vault"
    if [[ ! -d "${build_dir}" ]]; then
        git clone "https://github.com/hashicorp/vault.git" "${build_dir}"
    fi
    cd "${build_dir}"

    case "${HVAC_VAULT_VERSION}" in
        "head"|"master")
            git checkout master
            ;;
        "stable")
            latest_tag_hash=$(git rev-list --tags --max-count=1)
            git checkout "${latest_tag_hash}"
            ;;
    esac

    make bootstrap dev

    mkdir -p "${HVAC_VAULT_DIRECTORY}"
    mv "bin/vault" "${HVAC_VAULT_DIRECTORY}"
}

function install_vault_release() {
    cd "/tmp"

    unameOut="$(uname -s)"
    case "${unameOut}" in
        Linux*)     machine='linux';;
        Darwin*)    machine='darwin';;
        MINGW*)     machine='windows';;
        *)          machine='linux'
    esac

    if [[ "${HVAC_VAULT_LICENSE}" == "enterprise" ]]; then
        download_url="https://s3-us-west-2.amazonaws.com/hc-enterprise-binaries/vault/ent/${HVAC_VAULT_VERSION}/vault-enterprise_${HVAC_VAULT_VERSION}%2Bent_${machine}_amd64.zip"
    else
        download_url="https://releases.hashicorp.com/vault/${HVAC_VAULT_VERSION}/vault_${HVAC_VAULT_VERSION}_${machine}_amd64.zip"
    fi
    download_file="vault_${HVAC_VAULT_LICENSE}_${HVAC_VAULT_VERSION}.zip"

    curl -sL "${download_url}" -o "${download_file}"
    unzip "${download_file}"

    mkdir -p "${HVAC_VAULT_DIRECTORY}"
    mv "vault" "${HVAC_VAULT_DIRECTORY}"
}

HVAC_VAULT_VERSION=$(tr '[:upper:]' '[:lower:]' <<< "${HVAC_VAULT_VERSION}")
case "${HVAC_VAULT_VERSION}" in
    "head"|"master"|"stable")
        build_and_install_vault_ref
        ;;
    *)
        install_vault_release
        ;;
esac
