from unittest import TestCase

from hvac import exceptions
from parameterized import parameterized
from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestCert(HvacIntegrationTestCase, TestCase):
    TEST_MOUNT_POINT = "cert-test"
    TEST_ROLE_NAME = "testrole"
    TEST_CLIENT_CERTIFICATE_FILE = utils.get_config_file_path("client-cert.pem")
    cert = utils.create_client()._adapter._kwargs.get("cert")
    with open(TEST_CLIENT_CERTIFICATE_FILE, "r") as fp:
        TEST_CERTIFICATE = fp.read()

    def setUp(self):
        super().setUp()
        if "%s/" % self.TEST_MOUNT_POINT not in self.client.sys.list_auth_methods():
            self.client.sys.enable_auth_method(
                method_type="cert",
                path=self.TEST_MOUNT_POINT,
            )
        _ = self.client.auth.cert.create_ca_certificate_role(
            name=self.TEST_ROLE_NAME,
            certificate=self.TEST_CERTIFICATE,
            mount_point=self.TEST_MOUNT_POINT,
        )

    def tearDown(self):
        super().tearDown()

    def test_create_ca_certificate_role(self):
        response = self.client.auth.cert.create_ca_certificate_role(
            name="testrole2",
            certificate=self.TEST_CERTIFICATE,
            mount_point=self.TEST_MOUNT_POINT,
        )

        self.assertEqual(first=204, second=response.status_code)

    def test_create_ca_certificate_with_filename(self):
        response = self.client.auth.cert.create_ca_certificate_role(
            name="testrole2",
            certificate_file=self.TEST_CLIENT_CERTIFICATE_FILE,
            mount_point=self.TEST_MOUNT_POINT,
        )

        self.assertEqual(first=204, second=response.status_code)

    def test_create_ca_certificate_with_filename_deprecated(self):
        """This tests the deprecated feature of passing a certificate file via the certificate argument"""
        response = self.client.auth.cert.create_ca_certificate_role(
            name="testrole2",
            certificate=self.TEST_CLIENT_CERTIFICATE_FILE,
            mount_point=self.TEST_MOUNT_POINT,
        )

        self.assertEqual(first=204, second=response.status_code)

    def test_read_ca_certificate_role(self):
        response = self.client.auth.cert.read_ca_certificate_role(
            name=self.TEST_ROLE_NAME,
            mount_point=self.TEST_MOUNT_POINT,
        )

        self.assertEqual(
            first=self.TEST_ROLE_NAME,
            second=response["data"]["display_name"],
        )

    def test_list_certificate_roles(self):
        response = self.client.auth.cert.list_certificate_roles(
            mount_point=self.TEST_MOUNT_POINT,
        )

        self.assertEqual(first=response["data"]["keys"], second=[self.TEST_ROLE_NAME])

    def test_delete_certificate_role(self):
        self.client.auth.cert.create_ca_certificate_role(
            name="testrole2",
            certificate=self.TEST_CERTIFICATE,
            mount_point=self.TEST_MOUNT_POINT,
        )
        response = self.client.auth.cert.delete_certificate_role(
            name="testrole2",
            mount_point=self.TEST_MOUNT_POINT,
        )

        self.assertEqual(first=204, second=response.status_code)

    def test_configure_tls_certificate(self):
        response = self.client.auth.cert.configure_tls_certificate(
            mount_point=self.TEST_MOUNT_POINT
        )

        self.assertEqual(first=204, second=response.status_code)

    @parameterized.expand(
        [
            (TEST_ROLE_NAME, "", cert[0], cert[1], TEST_MOUNT_POINT),
            ("", "", cert[0], cert[1], TEST_MOUNT_POINT),
            ("testrole2", "", cert[0], cert[1], TEST_MOUNT_POINT),
            ("", "", "bad cert", cert[1], TEST_MOUNT_POINT),
            ("", "bad ca", cert[0], cert[1], TEST_MOUNT_POINT),
            ("", True, cert[0], cert[1], TEST_MOUNT_POINT),
            ("", False, " ", " ", TEST_MOUNT_POINT),
        ]
    )
    def test_login(self, name, cacert, cert_pem, key_pem, mount_point):
        if cacert or "bad" in [cacert, cert_pem, key_pem]:
            with self.assertRaises(exceptions.ParamValidationError):
                self.client.auth.cert.login(
                    name=name,
                    cacert=cacert,
                    cert_pem=cert_pem,
                    mount_point=mount_point,
                )
        elif (
            name != ""
            and name
            not in self.client.auth.cert.list_certificate_roles(
                mount_point=self.TEST_MOUNT_POINT,
            )["data"]["keys"]
        ):
            with self.assertRaises(exceptions.InvalidRequest):
                with self.assertRaises(OSError):
                    self.client.auth.cert.login(
                        name=name,
                        cacert=cacert,
                        cert_pem=cert_pem,
                        mount_point=mount_point,
                    )
        elif "/" not in cert_pem:
            with self.assertRaises(OSError):
                self.client.auth.cert.login(
                    name=name,
                    cacert=cacert,
                    cert_pem=cert_pem,
                    mount_point=mount_point,
                )
        else:
            response = self.client.auth.cert.login(
                name=name,
                cacert=cacert,
                cert_pem=cert_pem,
                mount_point=mount_point,
            )

            if name in [self.TEST_ROLE_NAME, ""] and (cacert, cert_pem, key_pem) == (
                "",
                self.cert[0],
                self.cert[1],
            ):
                self.assertIsInstance(response, dict)


class TestCertEnv(TestCert):
    use_env = True
