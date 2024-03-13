from unittest import TestCase

from parameterized import parameterized

from hvac import Client, exceptions
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestLDAP(HvacIntegrationTestCase, TestCase):
    DEFAULT_MOUNT_POINT = "ldap"

    def setUp(self):
        super().setUp()

    def tearDown(self):
        super().tearDown()

    @parameterized.expand(
        [
            ("CN=admin,DC=example,DC=org", "adminpassword", "ldap://openldap:1389", None, None, None, None, None, DEFAULT_MOUNT_POINT)
        ]
    )
    def test_configure(
        self,
        binddn=None,
        bindpass=None,
        url=None,
        password_policy=None,
        schema=None,
        userdn=None,
        userattr=None,
        upndomain=None,
        mount_point=DEFAULT_MOUNT_POINT,
        raises=None,
        exception_message="",
    ):
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.ldap.configure(
                    binddn, bindpass, url, password_policy, schema, 
                    userdn, userattr, upndomain, mount_point)

            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            configure_result = self.client.secrets.ldap.configure(
                binddn, bindpass, url, password_policy, schema, 
                userdn, userattr, upndomain, mount_point)
            self.assertEqual(
                first=204,
                second=configure_result.status_code,
            )
            print(str(configure_result))
            # Ensure when we query it's the same
            read_config_result = self.client.secrets.ldap.read_config(mount_point=mount_point)
            self.assertEqual(
                first=url,
                second=read_config_result["data"]["url"]
            )
            self.assertEqual(
                first=binddn,
                second=read_config_result["data"]["binddn"]
            )

    @parameterized.expand(
        [
            ("invalid", exceptions.InvalidPath),
            (DEFAULT_MOUNT_POINT),
        ]
    )
    def test_rotate_root(
            self, 
            mount_point=DEFAULT_MOUNT_POINT,
            raises=None, 
            exception_message=""
    ):
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.ldap.rotate_root(mount_point)

            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            rotate_result = self.client.secrets.ldap.rotate_root(mount_point)
            self.assertEqual(
                first=204,
                second=rotate_result.status_code,
            )

    @parameterized.expand(
        [
            ("vault-static", "vaulttest", "cn=vaulttest,ou=users,dc=example,dc=org", "24h", DEFAULT_MOUNT_POINT),
            ("vault-static-already-managed", "vaulttest", None, None, DEFAULT_MOUNT_POINT, exceptions.InvalidRequest),
        ]
    )
    def test_create_or_update_static_role(
        self,
        name,
        username=None,
        dn=None,
        rotation_period=None,
        mount_point=DEFAULT_MOUNT_POINT,
        raises=None, 
        exception_message=""
    ):
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.ldap.create_or_update_static_role(name, username, dn, rotation_period, mount_point=mount_point)

            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            static_result = self.client.secrets.ldap.create_or_update_static_role(name, username, dn, rotation_period, mount_point=mount_point)
            self.assertEqual(
                first=204,
                second=static_result.status_code,
            )

    @parameterized.expand(
        [
            ("vault-static", DEFAULT_MOUNT_POINT, False),
            ("vault-static-already-managed", DEFAULT_MOUNT_POINT, False, exceptions.InvalidPath),
            ("vault-static-1", DEFAULT_MOUNT_POINT, True),
        ]
    )
    def test_read_static_role(
        self, 
        name, 
        mount_point=DEFAULT_MOUNT_POINT,
        create_role_before_test=True,
        raises=None, 
        exception_message=""
    ):
        username="vaulttest"
        dn="cn=vaulttest,ou=users,dc=example,dc=org"
        rotation_period=600
        if create_role_before_test:
            username="vaulttest1"
            dn="cn=vaulttest1,ou=users,dc=example,dc=org"
            rotation_period=86400
            self.client.secrets.ldap.create_or_update_static_role(name, username, dn, rotation_period, mount_point=mount_point)

        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.ldap.read_static_role(name, mount_point=mount_point)

            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            static_result = self.client.secrets.ldap.read_static_role(name, mount_point=mount_point)
            self.assertEqual(
                first=username,
                second=static_result["data"]["username"],
            )
            self.assertEqual(
                first=dn,
                second=static_result["data"]["dn"],
            )
            self.assertEqual(
                first=rotation_period,
                second=static_result["data"]["rotation_period"],
            )

    @parameterized.expand(
        [
            ("invalid", exceptions.InvalidPath),
            (DEFAULT_MOUNT_POINT),
        ]
    )
    def test_list_static_roles(
        self, 
        mount_point=DEFAULT_MOUNT_POINT,
        raises=None, 
        exception_message=""
    ):
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.ldap.list_static_roles(mount_point)

            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            list_result = self.client.secrets.ldap.list_static_roles(mount_point)
            self.assertTrue(
                len(list_result["data"]) > 0
            )

    @parameterized.expand(
        [
            ("vault-static", "invalid", False, exceptions.InvalidPath),
            ("vault-static-deleteme", DEFAULT_MOUNT_POINT, True),
        ]
    )
    def test_delete_static_role(
        self, 
        name, 
        mount_point=DEFAULT_MOUNT_POINT,
        create_role_before_test=False,
        raises=None, 
        exception_message=""
    ):
        username="vaulttest2"
        dn="cn=vaulttest2,ou=users,dc=example,dc=org"
        rotation_period=86400
        if create_role_before_test:
            self.client.secrets.ldap.create_or_update_static_role(name, username, dn, rotation_period, mount_point=mount_point)
        
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.ldap.delete_static_role(name, mount_point)

            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            delete_result = self.client.secrets.ldap.delete_static_role(name, mount_point)
            self.assertEqual(
                first=204,
                second=delete_result.status_code,
            )

    @parameterized.expand(
        [
            ("vault-static", "invalid", exceptions.InvalidPath),
            ("vault-static", DEFAULT_MOUNT_POINT),
        ]
    )
    def test_generate_static_credentials(
        self, 
        name, 
        mount_point=DEFAULT_MOUNT_POINT,
        raises=None, 
        exception_message=""
    ):
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.ldap.generate_static_credentials(name, mount_point)

            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            credentials_result = self.client.secrets.ldap.generate_static_credentials(name, mount_point)
            self.assertIsNotNone(credentials_result['data'])
            self.assertIsNotNone(credentials_result['data']['password'])
