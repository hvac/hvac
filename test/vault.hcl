backend "inmem" {
}

listener "tcp" {
  tls_disable = 1
}

disable_mlock = true
