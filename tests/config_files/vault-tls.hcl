backend "inmem" {
}

listener "tcp" {
  tls_cert_file = "/tests/config_files/server-cert.pem"
  tls_key_file  = "/tests/config_files/server-key.pem"
  tls_min_version = "tls10"
  address = "0.0.0.0:8200"
}

disable_mlock = true

default_lease_ttl = "768h"
max_lease_ttl = "768h"
