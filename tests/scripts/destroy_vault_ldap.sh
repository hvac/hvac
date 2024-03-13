terraform -chdir="`dirname $0`"/../config_files/vault-ldap init || :
terraform -chdir="`dirname $0`"/../config_files/vault-ldap destroy -auto-approve || :
docker compose -f "`dirname $0`"/../config_files/vault-ldap/docker-compose.yml down vault openldap