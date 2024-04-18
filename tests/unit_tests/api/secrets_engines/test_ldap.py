from unittest import TestCase

import requests_mock
from parameterized import parameterized

from hvac.adapters import JSONAdapter
from hvac.api.secrets_engines import Ldap
from hvac.api.secrets_engines.ldap import DEFAULT_MOUNT_POINT


class TestLdap(TestCase):
    @parameterized.expand(
        [
            ("default mount point", DEFAULT_MOUNT_POINT),
            ("custom mount point", "other-ldap-tree"),
        ]
    )
    @requests_mock.Mocker()
    def test_configure(self, test_label, mount_point, requests_mocker):
        expected_status_code = 204
        mock_url = "http://localhost:8200/v1/{mount_point}/config".format(
            mount_point=mount_point,
        )
        requests_mocker.register_uri(
            method="POST",
            url=mock_url,
            status_code=expected_status_code,
        )
        ldap = Ldap(adapter=JSONAdapter())
        response = ldap.configure(
            binddn="cn=admin,dc=example,dc=com",
            bindpass="password",
            url="ldaps://ldap.example.com",
            mount_point=mount_point,
            upndomain="example.com",
            password_policy=None,
            userattr=None,
            schema=None,
            userdn="ou=users,dc=example,dc=com",
            connection_timeout="60s",
            request_timeout="30s",
            starttls=False,
            insecure_tls=False,
        )

        self.assertEqual(
            first=expected_status_code,
            second=response.status_code,
        )

    @parameterized.expand(
        [
            ("default mount point", DEFAULT_MOUNT_POINT),
            ("custom mount point", "other-ldap-tree"),
        ]
    )
    @requests_mock.Mocker()
    def test_read_configuration(self, test_label, mount_point, requests_mocker):
        expected_status_code = 200
        mock_response = {
            "lease_id": "",
            "warnings": None,
            "wrap_info": None,
            "auth": None,
            "lease_duration": 0,
            "request_id": "dd7c3635-8e1c-d454-7381-bf11970fe8de",
            "data": {
                "anonymous_group_search": False,
                "binddn": "cn=admin,dc=example,dc=com",
                "case_sensitive_names": False,
                "certificate": "",
                "connection_timeout": "",
                "deny_null_bind": True,
                "dereference_aliases": "never",
                "discoverdn": False,
                "groupattr": "",
                "groupdn": "",
                "groupfilter": "",
                "insecure_tls": False,
                "max_page_size": "0",
                "request_timeout": "90",
                "starttls": False,
                "tls_max_version": "tls12",
                "tls_min_version": "tls12",
                "upndomain": "",
                "url": "ldaps://ldap.example.com",
                "userattr": "",
                "userdn": "",
            },
            "renewable": False,
        }
        mock_url = "http://localhost:8200/v1/{mount_point}/config".format(
            mount_point=mount_point,
        )
        requests_mocker.register_uri(
            method="GET",
            url=mock_url,
            status_code=expected_status_code,
            json=mock_response,
        )
        ldap = Ldap(adapter=JSONAdapter())
        response = ldap.read_config(
            mount_point=mount_point,
        )
        self.assertEqual(
            first=mock_response,
            second=response,
        )

    @parameterized.expand(
        [
            ("default mount point", DEFAULT_MOUNT_POINT),
            ("custom mount point", "other-ldap-tree"),
        ]
    )
    @requests_mock.Mocker()
    def test_rotate_root(self, test_label, mount_point, requests_mocker):
        expected_status_code = 204
        mock_url = "http://localhost:8200/v1/{mount_point}/rotate-root".format(
            mount_point=mount_point,
        )
        requests_mocker.register_uri(
            method="POST",
            url=mock_url,
            status_code=expected_status_code,
        )
        ldap = Ldap(adapter=JSONAdapter())
        response = ldap.rotate_root(
            mount_point=mount_point,
        )
        self.assertEqual(
            first=expected_status_code,
            second=response.status_code,
        )

    @parameterized.expand(
        [
            ("default mount point", DEFAULT_MOUNT_POINT, "role1"),
            ("custom mount point", "other-ldap-tree", "role2"),
        ]
    )
    @requests_mock.Mocker()
    def test_create_or_update_static_role(
        self, test_label, mount_point, name, requests_mocker
    ):
        expected_status_code = 204
        mock_url = "http://localhost:8200/v1/{mount_point}/static-role/{name}".format(
            mount_point=mount_point,
            name=name,
        )
        requests_mocker.register_uri(
            method="POST",
            url=mock_url,
            status_code=expected_status_code,
        )
        ldap = Ldap(adapter=JSONAdapter())
        response = ldap.create_or_update_static_role(
            name=name,
            mount_point=mount_point,
        )
        self.assertEqual(
            first=expected_status_code,
            second=response.status_code,
        )

    @parameterized.expand(
        [
            ("default mount point", DEFAULT_MOUNT_POINT),
            ("custom mount point", "other-ldap-tree"),
        ]
    )
    @requests_mock.Mocker()
    def test_read_static_role(self, test_label, mount_point, requests_mocker):
        expected_status_code = 200
        role_name = "hvac"
        mock_response = {
            "lease_id": "",
            "warnings": None,
            "wrap_info": None,
            "auth": None,
            "lease_duration": 0,
            "request_id": "448bc87c-e948-ac5f-907c-9b01fb9d26c6",
            "data": {
                "username": "myuser",
                "dn": "cn=myuser,ou=users,dc=example,dc=com",
                "rotation_period": 600,
            },
            "renewable": False,
        }
        mock_url = "http://localhost:8200/v1/{mount_point}/static-role/{name}".format(
            mount_point=mount_point,
            name=role_name,
        )
        requests_mocker.register_uri(
            method="GET",
            url=mock_url,
            status_code=expected_status_code,
            json=mock_response,
        )
        ldap = Ldap(adapter=JSONAdapter())
        response = ldap.read_static_role(
            name=role_name,
            mount_point=mount_point,
        )
        self.assertEqual(
            first=mock_response,
            second=response,
        )

    @parameterized.expand(
        [
            ("default mount point", DEFAULT_MOUNT_POINT),
            ("custom mount point", "other-ldap-tree"),
        ]
    )
    @requests_mock.Mocker()
    def test_generate_static_credentials(
        self, test_label, mount_point, requests_mocker
    ):
        expected_status_code = 200
        role_name = "hvac"
        mock_response = {
            "dn": "uid=hashicorp,ou=Users,dc=example,dc=com",
            "last_vault_rotation": "2020-02-19T11:31:53.7812-05:00",
            "password": "LTNfyn7pS7XEZIxEYQ2sEAWic02PEP7zSvIs0xMqIjaU0ORzLhKOKVmYLxL1Xkyv",
            "last_password": "?@09AZSen9TzUwK7ZhafS7B0GuWGraQjfWEna5SwnmF/tVaKFqjXhhGV/Z0v/pBJ",
            "rotation_period": 86400,
            "ttl": 86072,
            "username": "hashicorp",
        }
        mock_url = "http://localhost:8200/v1/{mount_point}/static-cred/{name}".format(
            mount_point=mount_point,
            name=role_name,
        )
        requests_mocker.register_uri(
            method="GET",
            url=mock_url,
            status_code=expected_status_code,
            json=mock_response,
        )
        ldap = Ldap(adapter=JSONAdapter())
        response = ldap.generate_static_credentials(
            name=role_name,
            mount_point=mount_point,
        )
        self.assertEqual(
            first=mock_response,
            second=response,
        )

    @parameterized.expand(
        [
            ("default mount point", DEFAULT_MOUNT_POINT),
            ("custom mount point", "other-ldap-tree"),
        ]
    )
    @requests_mock.Mocker()
    def test_rotate_static_credentials(self, test_label, mount_point, requests_mocker):
        expected_status_code = 204
        role_name = "hvac"
        mock_url = "http://localhost:8200/v1/{mount_point}/rotate-role/{name}".format(
            mount_point=mount_point,
            name=role_name,
        )
        requests_mocker.register_uri(
            method="POST",
            url=mock_url,
            status_code=expected_status_code,
        )
        ldap = Ldap(adapter=JSONAdapter())
        response = ldap.rotate_static_credentials(
            name=role_name,
            mount_point=mount_point,
        )
        self.assertEqual(
            first=expected_status_code,
            second=response.status_code,
        )

    @parameterized.expand(
        [
            ("default mount point", DEFAULT_MOUNT_POINT),
            ("custom mount point", "other-ldap-tree"),
        ]
    )
    @requests_mock.Mocker()
    def test_delete_static_role(self, test_label, mount_point, requests_mocker):
        expected_status_code = 204
        role_name = "hvac"
        mock_url = "http://localhost:8200/v1/{mount_point}/static-role/{name}".format(
            mount_point=mount_point,
            name=role_name,
        )
        requests_mocker.register_uri(
            method="DELETE",
            url=mock_url,
            status_code=expected_status_code,
        )
        ldap = Ldap(adapter=JSONAdapter())
        response = ldap.delete_static_role(
            name=role_name,
            mount_point=mount_point,
        )
        self.assertEqual(
            first=expected_status_code,
            second=response.status_code,
        )

    @parameterized.expand(
        [
            ("default mount point", DEFAULT_MOUNT_POINT),
            ("custom mount point", "other-ldap-tree"),
        ]
    )
    @requests_mock.Mocker()
    def test_list_static_roles(self, test_label, mount_point, requests_mocker):
        expected_status_code = 200
        mock_response = {
            "lease_id": "",
            "warnings": None,
            "wrap_info": None,
            "auth": None,
            "lease_duration": 0,
            "request_id": "0c34cc02-2f75-7deb-a531-33cf7434a729",
            "data": {
                "roles": [
                    {
                        "username": "myuser",
                        "dn": "cn=myuser,ou=users,dc=example,dc=com",
                        "rotation_period": 600,
                    }
                ]
            },
            "renewable": False,
        }
        mock_url = "http://localhost:8200/v1/{mount_point}/static-role".format(
            mount_point=mount_point,
        )
        requests_mocker.register_uri(
            method="LIST",
            url=mock_url,
            status_code=expected_status_code,
            json=mock_response,
        )
        ldap = Ldap(adapter=JSONAdapter())
        response = ldap.list_static_roles(
            mount_point=mount_point,
        )
        self.assertEqual(
            first=mock_response,
            second=response,
        )
