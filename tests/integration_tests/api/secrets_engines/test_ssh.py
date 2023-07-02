import logging
from unittest import TestCase, skipIf

from parameterized import parameterized, param

from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase
from tests import utils


class TestPki(HvacIntegrationTestCase, TestCase):
    TEST_MOUNT_POINT = "ssh-integration-test"
    PRIVATE_SSH_KEY = "tests/config_files/ssh-key"
    PUBLIC_SSH_KEY = "tests/config_files/ssh-key.pub"

    def setUp(self):
        super().setUp()
        self.client.sys.enable_secrets_engine(
            backend_type="ssh",
            path=self.TEST_MOUNT_POINT,
        )

    def tearDown(self):
        self.client.sys.disable_secrets_engine(path=self.TEST_MOUNT_POINT)
        super().tearDown()

    # TODO: deprecate all dynamic SSH keys methods from hvac
    @parameterized.expand(
        [
            param(
                "success",
            ),
        ]
    )
    @skipIf(
        utils.vault_version_ge("1.13.0"), reason="Vault 1.13.0 dropped this feature."
    )
    def test_create_key(self, label, raises=False, exception_message=""):
        with open(self.PRIVATE_SSH_KEY) as key_file:
            private_key = key_file.read()

        create_key_response = self.client.secrets.ssh.create_or_update_key(
            name="test-key",
            key=private_key,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug("create_or_update_key_response: %s" % create_key_response)
        self.assertEqual(
            first=create_key_response.status_code,
            second=204,
        )

    # TODO: deprecate all dynamic SSH keys methods from hvac
    @parameterized.expand(
        [
            param(
                "success",
            ),
        ]
    )
    @skipIf(
        utils.vault_version_ge("1.13.0"), reason="Vault 1.13.0 dropped this feature."
    )
    def test_delete_key(self, label, raises=False, exception_message=""):
        with open(self.PRIVATE_SSH_KEY) as key_file:
            private_key = key_file.read()

        key_name = "test-key"
        self.client.secrets.ssh.create_or_update_key(
            name=key_name,
            key=private_key,
            mount_point=self.TEST_MOUNT_POINT,
        )

        delete_key_response = self.client.secrets.ssh.delete_key(
            name=key_name,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug("delete_key_response: %s" % delete_key_response)
        self.assertEqual(
            first=delete_key_response.status_code,
            second=204,
        )

    @parameterized.expand(
        [
            param(
                "success",
            ),
        ]
    )
    def test_create_role(self, label, raises=False, exception_message=""):
        role_name = "test_role"
        default_user = "root"
        key_type = "otp"

        create_role_response = self.client.secrets.ssh.create_role(
            name=role_name,
            default_user=default_user,
            key_type=key_type,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug("create_role_response: %s" % create_role_response)
        self.assertEqual(first=create_role_response.status_code, second=204)

    @parameterized.expand(
        [
            param(
                "success",
            ),
        ]
    )
    def test_read_role(self, label, raises=False, exception_message=""):
        role_name = "test_role"
        default_user = "root"
        key_type = "otp"

        self.client.secrets.ssh.create_role(
            name=role_name,
            default_user=default_user,
            key_type=key_type,
            mount_point=self.TEST_MOUNT_POINT,
        )

        read_role_response = self.client.secrets.ssh.read_role(
            name=role_name,
            mount_point=self.TEST_MOUNT_POINT,
        )
        print(read_role_response)
        logging.debug("read_role_response: %s" % read_role_response)
        self.assertEqual(
            first=read_role_response["data"],
            second={
                "allowed_users": "",
                "cidr_list": "",
                "default_user": "root",
                "exclude_cidr_list": "",
                "key_type": "otp",
                "port": 22,
            },
        )

    @parameterized.expand(
        [
            param(
                "success",
            ),
        ]
    )
    def test_list_roles(self, label, raises=False, exception_message=""):
        role_name = "test_role"
        default_user = "root"
        key_type = "otp"

        self.client.secrets.ssh.create_role(
            name=role_name,
            default_user=default_user,
            key_type=key_type,
            mount_point=self.TEST_MOUNT_POINT,
        )

        list_roles_response = self.client.secrets.ssh.list_roles(
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug("list_roles_response: %s" % list_roles_response)
        self.assertEqual(
            first=list_roles_response["data"],
            second={
                "key_info": {
                    "test_role": {
                        "key_type": "otp",
                    }
                },
                "keys": [
                    "test_role",
                ],
            },
        )

    @parameterized.expand(
        [
            param(
                "success",
            ),
        ]
    )
    def test_delete_role(self, label, raises=False, exception_message=""):
        role_name = "test_role"
        default_user = "root"
        key_type = "otp"

        self.client.secrets.ssh.create_role(
            name=role_name,
            default_user=default_user,
            key_type=key_type,
            mount_point=self.TEST_MOUNT_POINT,
        )

        delete_role_response = self.client.secrets.ssh.delete_role(
            name=role_name,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug("delete_role_response: %s" % delete_role_response)
        self.assertEqual(first=delete_role_response.status_code, second=204)

    @parameterized.expand(
        [
            param(
                "success",
            ),
        ]
    )
    def test_configure_zeroaddress_roles(
        self, label, raises=False, exception_message=""
    ):
        role_name = "test_role"
        default_user = "root"
        key_type = "otp"

        self.client.secrets.ssh.create_role(
            name=role_name,
            default_user=default_user,
            key_type=key_type,
            mount_point=self.TEST_MOUNT_POINT,
        )

        configure_zeroaddress_roles_response = (
            self.client.secrets.ssh.configure_zeroaddress_roles(
                roles=role_name,
                mount_point=self.TEST_MOUNT_POINT,
            )
        )

        logging.debug(
            "configure_zeroaddress_roles_response: %s"
            % configure_zeroaddress_roles_response
        )
        self.assertEqual(
            first=configure_zeroaddress_roles_response.status_code, second=204
        )

    @parameterized.expand(
        [
            param(
                "success",
            ),
        ]
    )
    def test_list_zeroaddress_roles(self, label, raises=False, exception_message=""):
        role_name = "test_role"
        default_user = "root"
        key_type = "otp"

        self.client.secrets.ssh.create_role(
            name=role_name,
            default_user=default_user,
            key_type=key_type,
            mount_point=self.TEST_MOUNT_POINT,
        )

        self.client.secrets.ssh.configure_zeroaddress_roles(
            roles=role_name,
            mount_point=self.TEST_MOUNT_POINT,
        )

        list_zeroaddress_roles_response = (
            self.client.secrets.ssh.list_zeroaddress_roles(
                mount_point=self.TEST_MOUNT_POINT,
            )
        )

        logging.debug(
            "list_zeroaddress_roles_response: %s" % list_zeroaddress_roles_response
        )
        self.assertEqual(
            first=list_zeroaddress_roles_response["data"],
            second={"roles": ["test_role"]},
        )

    @parameterized.expand(
        [
            param(
                "success",
            ),
        ]
    )
    def test_delete_zeroaddress_roles(self, label, raises=False, exception_message=""):
        role_name = "test_role"
        default_user = "root"
        key_type = "otp"

        self.client.secrets.ssh.create_role(
            name=role_name,
            default_user=default_user,
            key_type=key_type,
            mount_point=self.TEST_MOUNT_POINT,
        )

        self.client.secrets.ssh.configure_zeroaddress_roles(
            roles=role_name,
            mount_point=self.TEST_MOUNT_POINT,
        )

        delete_zeroaddress_roles_response = (
            self.client.secrets.ssh.delete_zeroaddress_role(
                mount_point=self.TEST_MOUNT_POINT,
            )
        )

        logging.debug(
            "delete_zeroaddress_roles_response: %s" % delete_zeroaddress_roles_response
        )
        self.assertEqual(
            first=delete_zeroaddress_roles_response.status_code, second=204
        )

    @parameterized.expand(
        [
            param(
                "success",
            ),
        ]
    )
    def test_generate_ssh_credentials(self, label, raises=False, exception_message=""):
        role_name = "test_role"
        default_user = "root"
        key_type = "otp"
        ip = "1.2.3.4"

        self.client.secrets.ssh.create_role(
            name=role_name,
            default_user=default_user,
            key_type=key_type,
            mount_point=self.TEST_MOUNT_POINT,
        )

        self.client.secrets.ssh.configure_zeroaddress_roles(
            roles=role_name,
            mount_point=self.TEST_MOUNT_POINT,
        )

        generate_ssh_creds_response = self.client.secrets.ssh.generate_ssh_credentials(
            name=role_name,
            username=default_user,
            ip=ip,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug("generate_ssh_creds_response: %s" % generate_ssh_creds_response)
        self.assertEqual(first=generate_ssh_creds_response["data"]["ip"], second=ip)

    @parameterized.expand(
        [
            param(
                "success",
            ),
        ]
    )
    def test_list_roles_by_ip(self, label, raises=False, exception_message=""):
        role_name = "test_role"
        default_user = "root"
        key_type = "otp"
        ip = "1.2.3.4"

        self.client.secrets.ssh.create_role(
            name=role_name,
            default_user=default_user,
            key_type=key_type,
            mount_point=self.TEST_MOUNT_POINT,
        )

        self.client.secrets.ssh.configure_zeroaddress_roles(
            roles=role_name,
            mount_point=self.TEST_MOUNT_POINT,
        )

        self.client.secrets.ssh.generate_ssh_credentials(
            name=role_name,
            username=default_user,
            ip=ip,
            mount_point=self.TEST_MOUNT_POINT,
        )

        list_roles_by_ip_response = self.client.secrets.ssh.list_roles_by_ip(
            ip=ip,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug("generate_ssh_creds_response: %s" % list_roles_by_ip_response)
        self.assertEqual(
            first=list_roles_by_ip_response["data"]["roles"], second=[role_name]
        )

    @parameterized.expand(
        [
            param(
                "success",
            ),
        ]
    )
    def test_verify_ssh_otp(self, label, raises=False, exception_message=""):
        role_name = "test_role"
        default_user = "root"
        key_type = "otp"
        ip = "1.2.3.4"

        self.client.secrets.ssh.create_role(
            name=role_name,
            default_user=default_user,
            key_type=key_type,
            mount_point=self.TEST_MOUNT_POINT,
        )

        self.client.secrets.ssh.configure_zeroaddress_roles(
            roles=role_name,
            mount_point=self.TEST_MOUNT_POINT,
        )

        generate_ssh_creds_response = self.client.secrets.ssh.generate_ssh_credentials(
            name=role_name,
            username=default_user,
            ip=ip,
            mount_point=self.TEST_MOUNT_POINT,
        )
        key = generate_ssh_creds_response["data"]["key"]

        verify_ssh_otp_response = self.client.secrets.ssh.verify_ssh_otp(
            otp=key,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug("verify_ssh_otp_response: %s" % verify_ssh_otp_response)
        self.assertEqual(
            first=verify_ssh_otp_response["data"]["ip"],
            second=ip,
        )

    @parameterized.expand(
        [
            param(
                "success",
            ),
        ]
    )
    def test_submit_ca_information(self, label, raises=False, exception_message=""):
        submit_ca_information_response = self.client.secrets.ssh.submit_ca_information(
            generate_signing_key=True,
            mount_point=self.TEST_MOUNT_POINT,
        )

        logging.debug(
            "submit_ca_information_response: %s" % submit_ca_information_response
        )
        self.assertIsInstance(
            obj=submit_ca_information_response["data"]["public_key"],
            cls=str,
        )

    @parameterized.expand(
        [
            param(
                "success",
            ),
        ]
    )
    def test_delete_ca_information(self, label, raises=False, exception_message=""):
        self.client.secrets.ssh.submit_ca_information(
            generate_signing_key=True,
            mount_point=self.TEST_MOUNT_POINT,
        )

        delete_ca_information_response = self.client.secrets.ssh.delete_ca_information(
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(
            "delete_ca_information_response: %s" % delete_ca_information_response
        )
        self.assertEqual(
            first=delete_ca_information_response.status_code,
            second=204,
        )

    @parameterized.expand(
        [
            param(
                "success",
            ),
        ]
    )
    def test_sign_ssh_key(self, label, raises=False, exception_message=""):
        role_name = "test_role"
        default_user = "root"
        key_type = "ca"

        self.client.secrets.ssh.submit_ca_information(
            generate_signing_key=True,
            mount_point=self.TEST_MOUNT_POINT,
        )

        self.client.secrets.ssh.create_role(
            name=role_name,
            default_user=default_user,
            key_type=key_type,
            allow_user_certificates=True,
            mount_point=self.TEST_MOUNT_POINT,
        )

        with open(self.PUBLIC_SSH_KEY) as key_file:
            public_key = key_file.read()

        read_public_key_response = self.client.secrets.ssh.sign_ssh_key(
            name=role_name,
            public_key=public_key,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug("read_public_key_response: %s" % read_public_key_response)
        self.assertIsInstance(
            obj=read_public_key_response["data"]["signed_key"],
            cls=str,
        )
