import logging
from unittest import TestCase
from unittest import skipIf

import requests_mock
from parameterized import parameterized

from hvac.adapters import JSONAdapter
from hvac.api.auth_methods import Kubernetes
from tests import utils


@skipIf(
    utils.vault_version_lt("0.8.3"),
    "Kubernetes auth method not available before Vault version 0.8.3",
)
class TestKubernetes(TestCase):
    TEST_MOUNT_POINT = "kubernetes-test"

    @parameterized.expand(
        [
            (
                "success",
                dict(),
                None,
            ),
        ]
    )
    @requests_mock.Mocker()
    def test_login(self, label, test_params, raises, requests_mocker):
        role_name = "hvac"
        test_policies = [
            "default",
            "dev",
            "prod",
        ]
        expected_status_code = 200
        mock_url = "http://localhost:8200/v1/auth/{mount_point}/login".format(
            mount_point=self.TEST_MOUNT_POINT,
        )
        mock_response = {
            "auth": {
                "client_token": "38fe9691-e623-7238-f618-c94d4e7bc674",
                "accessor": "78e87a38-84ed-2692-538f-ca8b9f400ab3",
                "policies": test_policies,
                "metadata": {
                    "role": role_name,
                    "service_account_name": "vault-auth",
                    "service_account_namespace": "default",
                    "service_account_secret_name": "vault-auth-token-pd21c",
                    "service_account_uid": "aa9aa8ff-98d0-11e7-9bb7-0800276d99bf",
                },
                "lease_duration": 2764800,
                "renewable": True,
            },
        }
        requests_mocker.register_uri(
            method="POST",
            url=mock_url,
            status_code=expected_status_code,
            json=mock_response,
        )
        kubernetes = Kubernetes(adapter=JSONAdapter())
        if raises is not None:
            with self.assertRaises(raises):
                kubernetes.login(
                    role=role_name,
                    jwt="my-jwt",
                    mount_point=self.TEST_MOUNT_POINT,
                    **test_params
                )
        else:
            login_response = kubernetes.login(
                role=role_name,
                jwt="my-jwt",
                mount_point=self.TEST_MOUNT_POINT,
                **test_params
            )
            logging.debug("login_response: %s" % login_response)
            self.assertEqual(
                first=login_response["auth"]["policies"],
                second=test_policies,
            )

    @parameterized.expand(
        [
            (
                "default mount point",
                None,
                "127.0.0.1:80",
                ["-----BEGIN CERTIFICATE-----test_key-----END CERTIFICATE-----"],
            ),
            (
                "custom mount point",
                "k8s",
                "some_k8s_host.com",
                ["-----BEGIN CERTIFICATE-----test_key-----END CERTIFICATE-----"],
            ),
        ]
    )
    @requests_mock.Mocker()
    def test_configure(
        self, test_label, mount_point, kubernetes_host, pem_keys, requests_mocker
    ):
        expected_status_code = 204
        mock_url = "http://localhost:8200/v1/auth/{}/config".format(
            "kubernetes" if mount_point is None else mount_point,
        )
        requests_mocker.register_uri(
            method="POST",
            url=mock_url,
            status_code=expected_status_code,
        )
        kubernetes = Kubernetes(adapter=JSONAdapter())

        test_arguments = dict(
            kubernetes_host=kubernetes_host,
            pem_keys=pem_keys,
        )
        if mount_point:
            test_arguments["mount_point"] = mount_point

        actual_response = kubernetes.configure(**test_arguments)

        self.assertEqual(
            first=expected_status_code,
            second=actual_response.status_code,
        )

    @parameterized.expand(
        [
            ("default mount point", None),
            ("custom mount point", "k8s"),
        ]
    )
    @requests_mock.Mocker()
    def test_read_configuration(self, test_label, mount_point, requests_mocker):
        expected_status_code = 200
        mock_response = {
            "auth": None,
            "data": {
                "kubernetes_ca_cert": "",
                "kubernetes_host": "127.0.0.1:80",
                "pem_keys": ["some key"],
                "token_reviewer_jwt": "",
            },
            "lease_duration": 0,
            "lease_id": "",
            "renewable": False,
            "request_id": "12687b5f-b4f5-2ba4-aae2-2a8d7e53ca55",
            "warnings": None,
            "wrap_info": None,
        }
        mock_url = "http://localhost:8200/v1/auth/{}/config".format(
            "kubernetes" if mount_point is None else mount_point,
        )
        requests_mocker.register_uri(
            method="GET",
            url=mock_url,
            status_code=expected_status_code,
            json=mock_response,
        )
        kubernetes = Kubernetes(adapter=JSONAdapter())

        test_arguments = dict()
        if mount_point:
            test_arguments["mount_point"] = mount_point

        actual_response = kubernetes.read_config(**test_arguments)

        self.assertEqual(
            first=mock_response["data"],
            second=actual_response,
        )

    @parameterized.expand(
        [
            (
                "default mount point",
                None,
                "application1",
                "*",
                "some-namespace",
                "serviceaccount_uid",
            ),
            (
                "custom mount point",
                "k8s",
                "application2",
                "some-service-account",
                "*",
                "serviceaccount_name",
            ),
        ]
    )
    @requests_mock.Mocker()
    def test_create_role(
        self,
        test_label,
        mount_point,
        role_name,
        bound_service_account_names,
        bound_service_account_namespaces,
        alias_name_source,
        requests_mocker,
    ):
        expected_status_code = 204
        mock_url = "http://localhost:8200/v1/auth/{}/role/{}".format(
            "kubernetes" if mount_point is None else mount_point,
            role_name,
        )
        requests_mocker.register_uri(
            method="POST",
            url=mock_url,
            status_code=expected_status_code,
        )
        kubernetes = Kubernetes(adapter=JSONAdapter())

        test_arguments = dict(
            name=role_name,
            bound_service_account_names=bound_service_account_names,
            bound_service_account_namespaces=bound_service_account_namespaces,
            alias_name_source=alias_name_source,
        )
        if mount_point:
            test_arguments["mount_point"] = mount_point
        actual_response = kubernetes.create_role(**test_arguments)

        self.assertEqual(
            first=expected_status_code,
            second=actual_response.status_code,
        )

    @parameterized.expand(
        [
            ("default mount point", None, "application1"),
            ("custom mount point", "k8s", "application2"),
        ]
    )
    @requests_mock.Mocker()
    def test_read_role(self, test_label, mount_point, role_name, requests_mocker):
        expected_status_code = 200
        mock_response = {
            "auth": None,
            "data": {
                "bind_secret_id": True,
                "bound_cidr_list": "",
                "period": 0,
                "policies": ["default"],
                "secret_id_num_uses": 0,
                "secret_id_ttl": 0,
                "token_max_ttl": 900,
                "token_num_uses": 0,
                "token_ttl": 600,
            },
            "lease_duration": 0,
            "lease_id": "",
            "renewable": False,
            "request_id": "0aab655f-ecd2-b3d4-3817-35b5bdfd3f28",
            "warnings": None,
            "wrap_info": None,
        }
        mock_url = "http://localhost:8200/v1/auth/{}/role/{}".format(
            "kubernetes" if mount_point is None else mount_point,
            role_name,
        )
        requests_mocker.register_uri(
            method="GET",
            url=mock_url,
            status_code=expected_status_code,
            json=mock_response,
        )
        kubernetes = Kubernetes(adapter=JSONAdapter())

        test_arguments = dict(
            name=role_name,
        )
        if mount_point:
            test_arguments["mount_point"] = mount_point

        actual_response = kubernetes.read_role(**test_arguments)

        self.assertEqual(
            first=mock_response["data"],
            second=actual_response,
        )

    @parameterized.expand(
        [
            ("default mount point", None, ["test-role-1", "test-role-2"]),
            ("custom mount point", "k8s", ["test-role"]),
        ]
    )
    @requests_mock.Mocker()
    def test_list_roles(self, test_label, mount_point, role_names, requests_mocker):
        expected_status_code = 200
        mock_response = {
            "auth": None,
            "data": {
                "keys": role_names,
            },
            "lease_duration": 0,
            "lease_id": "",
            "renewable": False,
            "request_id": "e4c219fb-0a78-2be2-8d3c-b3715dccb920",
            "warnings": None,
            "wrap_info": None,
        }
        mock_url = "http://localhost:8200/v1/auth/{}/role".format(
            "kubernetes" if mount_point is None else mount_point,
        )
        requests_mocker.register_uri(
            method="LIST",
            url=mock_url,
            status_code=expected_status_code,
            json=mock_response,
        )
        kubernetes = Kubernetes(adapter=JSONAdapter())

        test_arguments = dict()
        if mount_point:
            test_arguments["mount_point"] = mount_point
        actual_response = kubernetes.list_roles(**test_arguments)

        # ensure we received our mock response data back successfully
        self.assertEqual(mock_response["data"], actual_response)

    @parameterized.expand(
        [
            ("default mount point", None, "application1"),
            ("custom mount point", "k8s", "application2"),
        ]
    )
    @requests_mock.Mocker()
    def test_delete_role(self, test_label, mount_point, role_name, requests_mocker):
        expected_status_code = 204
        mock_url = "http://localhost:8200/v1/auth/{}/role/{}".format(
            "kubernetes" if mount_point is None else mount_point,
            role_name,
        )
        requests_mocker.register_uri(
            method="DELETE",
            url=mock_url,
            status_code=expected_status_code,
        )
        kubernetes = Kubernetes(adapter=JSONAdapter())

        test_arguments = dict(
            name=role_name,
        )
        if mount_point:
            test_arguments["mount_point"] = mount_point

        actual_response = kubernetes.delete_role(**test_arguments)

        self.assertEqual(
            first=expected_status_code,
            second=actual_response.status_code,
        )
