#!/usr/bin/env python
# -*- coding: utf-8 -*-
from ldap_test import LdapServer
from tests.utils import get_free_port


class MockLdapServer(object):
    ldap_url = "ldap://ldap.python-hvac.org"
    ldap_group_name = "vault-users"
    ldap_user_name = "somedude"
    ldap_user_password = "hvacrox"
    ldap_base_dc = "hvac"
    ldap_base_dn = "dc={dc},dc=network".format(dc=ldap_base_dc)
    ldap_bind_dn = "cn=admin,{base_dn}".format(base_dn=ldap_base_dn)
    ldap_bind_password = "notaverygoodpassword"
    ldap_users_dn = "dc=users,{base_dn}".format(base_dn=ldap_base_dn)
    ldap_groups_ou = "groups"
    ldap_groups_dn = "ou={ou},{base_dn}".format(ou=ldap_groups_ou, base_dn=ldap_base_dn)
    ldap_login_user_dn = "uid={username},{users_dn}".format(
        username=ldap_user_name, users_dn=ldap_users_dn
    )
    ldap_entries = [
        {"objectclass": "domain", "dn": ldap_users_dn, "attributes": {"dc": "users"}},
        {
            "objectclass": ["inetorgperson", "posixgroup", "top"],
            "dn": ldap_login_user_dn,
            "attributes": {"uid": ldap_user_name, "userpassword": ldap_user_password},
        },
        {
            "objectclass": "organizationalunit",
            "dn": ldap_groups_dn,
            "attributes": {
                "ou": "groups",
            },
        },
        {
            "objectclass": "groupofnames",
            "dn": "cn={cn},{groups_dn}".format(
                cn=ldap_group_name, groups_dn=ldap_groups_dn
            ),
            "attributes": {
                "cn": ldap_group_name,
                "member": ldap_login_user_dn,
            },
        },
    ]

    def __init__(self):
        self.server_port = get_free_port()
        self.ldap_server = LdapServer(
            {
                "port": self.server_port,
                "bind_dn": self.ldap_bind_dn,
                "password": self.ldap_bind_password,
                "base": {
                    "objectclass": ["domain"],
                    "dn": self.ldap_base_dn,
                    "attributes": {"dc": self.ldap_base_dc},
                },
                "entries": self.ldap_entries,
            }
        )

    @property
    def url(self):
        return "ldap://localhost:{port}".format(port=self.server_port)

    def start(self):
        self.ldap_server.start()

    def stop(self):
        self.ldap_server.stop()
