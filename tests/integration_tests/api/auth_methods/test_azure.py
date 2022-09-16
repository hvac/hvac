import logging
from unittest import TestCase
from unittest import skipIf

from parameterized import parameterized, param

from hvac import exceptions
from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


@skipIf(
    utils.vault_version_lt("0.10.0"),
    "Azure auth method not available before Vault version 0.10.0",
)
class TestAzure(HvacIntegrationTestCase, TestCase):
    TEST_MOUNT_POINT = "azure-test"

    def setUp(self):
        super().setUp()
        if "%s/" % self.TEST_MOUNT_POINT not in self.client.sys.list_auth_methods():
            self.client.sys.enable_auth_method(
                method_type="azure",
                path=self.TEST_MOUNT_POINT,
            )

    def tearDown(self):
        super().tearDown()
        self.client.sys.disable_auth_method(
            path=self.TEST_MOUNT_POINT,
        )

    @parameterized.expand(
        [
            param(
                "tenant_id and resource",
            ),
            param(
                "client id and secret",
                client_id="my-client-id",
                client_secret="my-client-secert",
            ),
            param(
                "invalid environment",
                environment="AzurePublicCats",
                raises=exceptions.ParamValidationError,
                exception_message="invalid environment argument provided",
            ),
        ]
    )
    def test_configure(
        self,
        label,
        client_id=None,
        client_secret=None,
        environment="AzurePublicCloud",
        raises=None,
        exception_message="",
    ):
        tenant_id = "my-tenant-id"
        resource = "my-resource"
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.auth.azure.configure(
                    tenant_id=tenant_id,
                    resource=resource,
                    client_id=client_id,
                    client_secret=client_secret,
                    environment=environment,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            configure_response = self.client.auth.azure.configure(
                tenant_id=tenant_id,
                resource=resource,
                client_id=client_id,
                client_secret=client_secret,
                environment=environment,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("configure_response: %s" % configure_response)
            self.assertEqual(
                first=bool(configure_response),
                second=True,
            )

    @parameterized.expand(
        [
            param(
                "success",
            ),
            param(
                "no config written yet",
                write_config_first=False,
                raises=exceptions.InvalidPath,
            ),
        ]
    )
    def test_read_config(self, label, write_config_first=True, raises=None):
        expected_config = {
            "tenant_id": "my-tenant-id",
            "resource": "my-resource",
        }
        if write_config_first:
            self.client.auth.azure.configure(
                mount_point=self.TEST_MOUNT_POINT, **expected_config
            )
        if raises is not None:
            with self.assertRaises(raises):
                self.client.auth.azure.read_config(
                    mount_point=self.TEST_MOUNT_POINT,
                )
        else:
            read_config_response = self.client.auth.azure.read_config(
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("read_config_response: %s" % read_config_response)
            for k, v in expected_config.items():
                self.assertEqual(
                    first=v,
                    second=read_config_response[k],
                )

    @parameterized.expand(
        [
            ("success",),
        ]
    )
    def test_delete_config(self, label):
        delete_config_response = self.client.auth.azure.delete_config(
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug("delete_config_response: %s" % delete_config_response)
        self.assertEqual(
            first=bool(delete_config_response),
            second=True,
        )

    @parameterized.expand(
        [
            param(
                "success",
                bound_service_principal_ids=["my-sp-id"],
            ),
            param(
                "CSV policies arg",
                bound_service_principal_ids=["my-sp-id"],
                policies="cats,dogs",
            ),
            param(
                "list policies arg",
                bound_service_principal_ids=["my-sp-id"],
                policies=["cats", "dogs"],
            ),
            param(
                "no bound constraints",
                raises=exceptions.InvalidRequest,
                exception_message="must have at least one bound constraint when creating/updating a role",
            ),
            param(
                "wrong policy arg type",
                bound_service_principal_ids=["my-sp-id"],
                policies={"dict": "bad"},
                raises=exceptions.ParamValidationError,
                exception_message="unsupported policies argument provided",
            ),
            param(
                "mixed policy arg type",
                bound_service_principal_ids=["my-sp-id"],
                policies=["cats", "dogs", None, 42],
                raises=exceptions.ParamValidationError,
                exception_message="unsupported policies argument provided",
            ),
        ]
    )
    def test_create_role(
        self,
        label,
        policies=None,
        bound_service_principal_ids=None,
        raises=None,
        exception_message="",
    ):
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.auth.azure.create_role(
                    name="my-role",
                    policies=policies,
                    bound_service_principal_ids=bound_service_principal_ids,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            create_role_response = self.client.auth.azure.create_role(
                name="my-role",
                policies=policies,
                bound_service_principal_ids=bound_service_principal_ids,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("create_role_response: %s" % create_role_response)
            self.assertEqual(
                first=bool(create_role_response),
                second=True,
            )

    @parameterized.expand(
        [
            param(
                "success",
            ),
            param(
                "nonexistent role name",
                configure_role_first=False,
                raises=exceptions.InvalidPath,
            ),
        ]
    )
    def test_read_role(
        self,
        label,
        role_name="hvac",
        configure_role_first=True,
        raises=None,
        exception_message="",
    ):
        bound_service_principal_ids = ["some-dummy-sp-id"]
        if configure_role_first:
            create_role_response = self.client.auth.azure.create_role(
                name=role_name,
                bound_service_principal_ids=bound_service_principal_ids,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("create_role_response: %s" % create_role_response)

        if raises is not None:
            with self.assertRaises(raises):
                self.client.auth.azure.read_role(
                    name=role_name,
                    mount_point=self.TEST_MOUNT_POINT,
                )
        else:
            read_role_response = self.client.auth.azure.read_role(
                name=role_name,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("read_role_response: %s" % read_role_response)
            self.assertEqual(
                first=read_role_response["bound_service_principal_ids"],
                second=bound_service_principal_ids,
            )

    @parameterized.expand(
        [
            param(
                "success",
            ),
            param(
                "no roles",
                num_roles_to_create=0,
                raises=exceptions.InvalidPath,
            ),
            param(
                "no config",
                write_config_first=False,
            ),
        ]
    )
    def test_list_roles(
        self, label, num_roles_to_create=1, write_config_first=True, raises=None
    ):
        if write_config_first:
            self.client.auth.azure.configure(
                tenant_id="my-tenant-id",
                resource="my-resource",
                mount_point=self.TEST_MOUNT_POINT,
            )
        roles_to_create = ["hvac%s" % n for n in range(0, num_roles_to_create)]
        bound_service_principal_ids = ["some-dummy-sp-id"]
        logging.debug("roles_to_create: %s" % roles_to_create)
        for role_to_create in roles_to_create:
            create_role_response = self.client.auth.azure.create_role(
                name=role_to_create,
                bound_service_principal_ids=bound_service_principal_ids,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("create_role_response: %s" % create_role_response)

        if raises is not None:
            with self.assertRaises(raises):
                self.client.auth.azure.list_roles(
                    mount_point=self.TEST_MOUNT_POINT,
                )
        else:
            list_roles_response = self.client.auth.azure.list_roles(
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("read_role_response: %s" % list_roles_response)
            self.assertEqual(
                first=list_roles_response["keys"],
                second=roles_to_create,
            )

    @parameterized.expand(
        [
            param(
                "success",
            ),
            param(
                "nonexistent role name",
                configure_role_first=False,
            ),
        ]
    )
    def test_delete_role(self, label, configure_role_first=True, raises=None):
        role_name = "hvac"
        bound_service_principal_ids = ["some-dummy-sp-id"]
        if configure_role_first:
            create_role_response = self.client.auth.azure.create_role(
                name=role_name,
                bound_service_principal_ids=bound_service_principal_ids,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("create_role_response: %s" % create_role_response)

        if raises is not None:
            with self.assertRaises(raises):
                self.client.auth.azure.delete_role(
                    name=role_name,
                    mount_point=self.TEST_MOUNT_POINT,
                )
        else:
            delete_role_response = self.client.auth.azure.delete_role(
                name=role_name,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("delete_role_response: %s" % delete_role_response)
            self.assertEqual(
                first=bool(delete_role_response),
                second=True,
            )
