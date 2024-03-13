terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "3.22.0"
    }
  }
}

variable "token" {
  type = string
  default = "root"
}

provider "vault" {
  address = "https://localhost:8200"
  token   = var.token
  skip_tls_verify = true
}

resource "vault_ldap_secret_backend" "config" {
  path         = "ldap"
  binddn       = "CN=admin,dc=example,dc=org"
  bindpass     = "adminpassword"
  url          = "ldap://openldap:1389"
  insecure_tls = "true"
  userdn       = "dc=example,dc=org"
}

resource "vault_ldap_secret_backend_dynamic_role" "vault-dynamic" {
  mount         = vault_ldap_secret_backend.config.path
  role_name     = "vault-dynamic"
  creation_ldif = <<EOT
dn: cn={{.Username}},ou=users,dc=example,dc=org
objectClass: person
objectClass: top
cn: learn
sn: {{.Password | utf16le | base64}}
userPassword: {{.Password}}
EOT
  deletion_ldif = <<EOT
dn: cn={{.Username}},ou=users,dc=example,dc=org
changetype: delete
EOT
}

resource "vault_ldap_secret_backend_static_role" "vault-static" {
  mount           = vault_ldap_secret_backend.config.path
  username        = "vaulttest"
  dn              = "cn=vaulttest,ou=users,dc=example,dc=org"
  role_name       = "vault-static"
  rotation_period = 600
}