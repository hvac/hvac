import logging
from unittest import TestCase

from parameterized import parameterized, param

from hvac import exceptions
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestOkta(HvacIntegrationTestCase, TestCase):
    TEST_MOUNT_POINT = "test-okta"
    TEST_ORG_NAME = "hvac-test"
    TEST_BASE_URL = "python-hvac.org"
    TEST_USERNAME = "hvac-person"
    TEST_GROUP = "hvac-group"

    def setUp(self):
        super().setUp()
        self.client.sys.enable_auth_method(
            method_type="okta",
            path=self.TEST_MOUNT_POINT,
        )

    def tearDown(self):
        self.client.sys.disable_auth_method(
            path=self.TEST_MOUNT_POINT,
        )
        super().tearDown()

    @parameterized.expand(
        [
            param(
                "success",
            ),
        ]
    )
    def test_configure(self, label, raises=None, exception_msg=""):
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.auth.okta.configure(
                    org_name=self.TEST_ORG_NAME,
                    base_url=self.TEST_BASE_URL,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_msg,
                container=str(cm.exception),
            )
        else:
            configure_response = self.client.auth.okta.configure(
                org_name=self.TEST_ORG_NAME,
                base_url=self.TEST_BASE_URL,
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
                "not configured",
                configure_first=False,
                raises=exceptions.InvalidPath,
            ),
        ]
    )
    def test_read_config(
        self, label, configure_first=True, raises=None, exception_msg=""
    ):
        if configure_first:
            configure_response = self.client.auth.okta.configure(
                org_name=self.TEST_ORG_NAME,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("configure_response: %s" % configure_response)

        if raises:
            with self.assertRaises(raises) as cm:
                self.client.auth.gcp.read_config(
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_msg,
                container=str(cm.exception),
            )
        else:
            read_config_response = self.client.auth.okta.read_config(
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("configure_response: %s" % read_config_response)
            self.assertEqual(
                first=read_config_response["data"]["org_name"],
                second=self.TEST_ORG_NAME,
            )

    @parameterized.expand(
        [
            param(
                "success",
            ),
            param(
                "no configuration",
                configure_first=False,
                raises=exceptions.InvalidPath,
            ),
        ]
    )
    def test_list_users(
        self, label, configure_first=True, raises=None, exception_msg=""
    ):
        if configure_first:
            configure_response = self.client.auth.okta.configure(
                org_name=self.TEST_ORG_NAME,
                base_url=self.TEST_BASE_URL,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("configure_response: %s" % configure_response)
            register_user_response = self.client.auth.okta.register_user(
                username=self.TEST_USERNAME,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("register_user_response: %s" % register_user_response)
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.auth.okta.list_users(
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_msg,
                container=str(cm.exception),
            )
        else:
            list_users_response = self.client.auth.okta.list_users(
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("list_users_response: %s" % list_users_response)
            self.assertEqual(
                first=list_users_response["data"]["keys"],
                second=[self.TEST_USERNAME],
            )

    @parameterized.expand(
        [
            param(
                "double register",
            ),
            param(
                "success",
                configure_first=False,
            ),
        ]
    )
    def test_register_user(
        self, label, configure_first=True, raises=None, exception_msg=""
    ):
        if configure_first:
            configure_response = self.client.auth.okta.configure(
                org_name=self.TEST_ORG_NAME,
                base_url=self.TEST_BASE_URL,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("configure_response: %s" % configure_response)
            register_user_response = self.client.auth.okta.register_user(
                username=self.TEST_USERNAME,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("register_user_response: %s" % register_user_response)
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.auth.okta.register_user(
                    username=self.TEST_USERNAME,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_msg,
                container=str(cm.exception),
            )
        else:
            register_user_response = self.client.auth.okta.register_user(
                username=self.TEST_USERNAME,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("register_user_response: %s" % register_user_response)
            self.assertEqual(
                first=bool(register_user_response),
                second=True,
            )

    @parameterized.expand(
        [
            param(
                "success",
            ),
            param(
                "no configuration",
                configure_first=False,
                raises=exceptions.InvalidPath,
            ),
        ]
    )
    def test_read_user(
        self, label, configure_first=True, raises=None, exception_msg=""
    ):
        if configure_first:
            configure_response = self.client.auth.okta.configure(
                org_name=self.TEST_ORG_NAME,
                base_url=self.TEST_BASE_URL,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("configure_response: %s" % configure_response)
            register_user_response = self.client.auth.okta.register_user(
                username=self.TEST_USERNAME,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("register_user_response: %s" % register_user_response)
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.auth.okta.read_user(
                    username=self.TEST_USERNAME,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_msg,
                container=str(cm.exception),
            )
        else:
            read_user_response = self.client.auth.okta.read_user(
                username=self.TEST_USERNAME,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("read_user_response: %s" % read_user_response)
            self.assertIn(
                member="policies",
                container=read_user_response["data"],
            )

    @parameterized.expand(
        [
            param(
                "success",
            ),
            param(
                "no configuration",
                configure_first=False,
            ),
        ]
    )
    def test_delete_user(
        self, label, configure_first=True, raises=None, exception_msg=""
    ):
        if configure_first:
            configure_response = self.client.auth.okta.configure(
                org_name=self.TEST_ORG_NAME,
                base_url=self.TEST_BASE_URL,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("configure_response: %s" % configure_response)
            register_user_response = self.client.auth.okta.register_user(
                username=self.TEST_USERNAME,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("register_user_response: %s" % register_user_response)
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.auth.okta.delete_user(
                    username=self.TEST_USERNAME,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_msg,
                container=str(cm.exception),
            )
        else:
            delete_user_response = self.client.auth.okta.delete_user(
                username=self.TEST_USERNAME,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("delete_user_response: %s" % delete_user_response)
            self.assertEqual(
                first=bool(delete_user_response),
                second=True,
            )

    @parameterized.expand(
        [
            param(
                "success",
            ),
            param(
                "no configuration",
                configure_first=False,
                raises=exceptions.InvalidPath,
            ),
        ]
    )
    def test_list_groups(
        self, label, configure_first=True, raises=None, exception_msg=""
    ):
        if configure_first:
            configure_response = self.client.auth.okta.configure(
                org_name=self.TEST_ORG_NAME,
                base_url=self.TEST_BASE_URL,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("configure_response: %s" % configure_response)
            register_group_response = self.client.auth.okta.register_group(
                name=self.TEST_GROUP,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("register_group_response: %s" % register_group_response)
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.auth.okta.list_groups(
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_msg,
                container=str(cm.exception),
            )
        else:
            list_groups_response = self.client.auth.okta.list_groups(
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("list_groups_response: %s" % list_groups_response)
            self.assertEqual(
                first=list_groups_response["data"]["keys"],
                second=[self.TEST_GROUP],
            )

    @parameterized.expand(
        [
            param(
                "double register",
            ),
            param(
                "success",
                configure_first=False,
            ),
        ]
    )
    def test_register_group(
        self, label, configure_first=True, raises=None, exception_msg=""
    ):
        if configure_first:
            configure_response = self.client.auth.okta.configure(
                org_name=self.TEST_ORG_NAME,
                base_url=self.TEST_BASE_URL,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("configure_response: %s" % configure_response)
            register_group_response = self.client.auth.okta.register_group(
                name=self.TEST_GROUP,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("register_group_response: %s" % register_group_response)
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.auth.okta.register_group(
                    name=self.TEST_GROUP,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_msg,
                container=str(cm.exception),
            )
        else:
            register_group_response = self.client.auth.okta.register_group(
                name=self.TEST_GROUP,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("register_group_response: %s" % register_group_response)
            self.assertEqual(
                first=bool(register_group_response),
                second=True,
            )

    @parameterized.expand(
        [
            param(
                "success",
            ),
            param(
                "no configuration",
                configure_first=False,
                raises=exceptions.InvalidPath,
            ),
        ]
    )
    def test_read_group(
        self, label, configure_first=True, raises=None, exception_msg=""
    ):
        if configure_first:
            configure_response = self.client.auth.okta.configure(
                org_name=self.TEST_ORG_NAME,
                base_url=self.TEST_BASE_URL,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("configure_response: %s" % configure_response)
            register_group_response = self.client.auth.okta.register_group(
                name=self.TEST_GROUP,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("register_group_response: %s" % register_group_response)
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.auth.okta.read_group(
                    name=self.TEST_GROUP,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_msg,
                container=str(cm.exception),
            )
        else:
            read_group_response = self.client.auth.okta.read_group(
                name=self.TEST_GROUP,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("read_group_response: %s" % read_group_response)
            self.assertIn(
                member="policies",
                container=read_group_response["data"],
            )

    @parameterized.expand(
        [
            param(
                "success",
            ),
            param(
                "no configuration",
                configure_first=False,
            ),
        ]
    )
    def test_delete_group(
        self, label, configure_first=True, raises=None, exception_msg=""
    ):
        if configure_first:
            configure_response = self.client.auth.okta.configure(
                org_name=self.TEST_ORG_NAME,
                base_url=self.TEST_BASE_URL,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("configure_response: %s" % configure_response)
            register_group_response = self.client.auth.okta.register_group(
                name=self.TEST_GROUP,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("register_group_response: %s" % register_group_response)
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.auth.okta.delete_group(
                    name=self.TEST_GROUP,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_msg,
                container=str(cm.exception),
            )
        else:
            delete_group_response = self.client.auth.okta.delete_group(
                name=self.TEST_GROUP,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("delete_group_response: %s" % delete_group_response)
            self.assertEqual(
                first=bool(delete_group_response),
                second=True,
            )
