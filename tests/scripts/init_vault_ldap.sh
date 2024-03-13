docker compose -f "`dirname $0`"/../config_files/vault-ldap/docker-compose.yml up -d vault openldap
terraform -chdir="`dirname $0`"/../config_files/vault-ldap init
terraform -chdir="`dirname $0`"/../config_files/vault-ldap apply -auto-approve