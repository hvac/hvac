import logging
from unittest import TestCase
from unittest import skipIf

from parameterized import parameterized, param

from hvac import exceptions
from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


@skipIf(
    utils.vault_version_lt("0.9.0"),
    "Identity secrets engine open sourced in Vault version >=0.9.0",
)
class TestIdentity(HvacIntegrationTestCase, TestCase):
    TEST_APPROLE_PATH = "identity-test-approle"
    TEST_APPROLE_ROLE_ID = "identity-test-role-id"
    TEST_MOUNT_POINT = "identity"
    TEST_ENTITY_NAME = "test-entity"
    TEST_ALIAS_NAME = "test-alias"
    TEST_GROUP_NAME = "test-group"
    TEST_MEMBER_GROUP_NAME = "test-group-member"
    TEST_GROUP_ALIAS_NAME = "test-group-alias"

    test_approle_accessor = None

    def setUp(self):
        super().setUp()
        if "%s/" % self.TEST_APPROLE_PATH not in self.client.sys.list_auth_methods():
            self.client.sys.enable_auth_method(
                method_type="approle",
                path=self.TEST_APPROLE_PATH,
            )
        list_auth_response = self.client.sys.list_auth_methods()
        self.test_approle_accessor = list_auth_response["data"][
            "%s/" % self.TEST_APPROLE_PATH
        ]["accessor"]

    def tearDown(self):
        super().tearDown()
        self.tear_down_entities()
        self.tear_down_entity_aliases()
        self.tear_down_groups()
        self.client.sys.disable_auth_method(
            path=self.TEST_APPROLE_PATH,
        )

    def tear_down_entities(self):
        try:
            list_entities_response = self.client.secrets.identity.list_entities(
                mount_point=self.TEST_MOUNT_POINT
            )
            logging.debug(
                "list_entities_response in tearDown: %s" % list_entities_response
            )
            entity_ids = list_entities_response["data"]["keys"]
        except exceptions.InvalidPath:
            logging.debug(
                "InvalidPath raised when calling list_entities_by_id in tearDown..."
            )
            entity_ids = []
        for entity_id in entity_ids:
            logging.debug("Deleting entity ID: %s" % entity_id)
            self.client.secrets.identity.delete_entity(
                entity_id=entity_id,
                mount_point=self.TEST_MOUNT_POINT,
            )

    def tear_down_entity_aliases(self):
        try:
            list_entity_aliases_response = (
                self.client.secrets.identity.list_entity_aliases(
                    mount_point=self.TEST_MOUNT_POINT
                )
            )
            logging.debug(
                "list_entity_aliases_response in tearDown: %s"
                % list_entity_aliases_response
            )
            alias_ids = list_entity_aliases_response["keys"]
        except exceptions.InvalidPath:
            logging.debug(
                "InvalidPath raised when calling list_entities_by_id in tearDown..."
            )
            alias_ids = []
        for alias_id in alias_ids:
            logging.debug("Deleting alias ID: %s" % alias_id)
            self.client.secrets.identity.delete_entity_alias(
                alias_id=alias_id,
                mount_point=self.TEST_MOUNT_POINT,
            )

    def tear_down_groups(self):
        try:
            list_group_response = self.client.secrets.identity.list_groups(
                mount_point=self.TEST_MOUNT_POINT
            )
            logging.debug("list_group_response in tearDown: %s" % list_group_response)
            group_ids = list_group_response["data"]["keys"]
        except exceptions.InvalidPath:
            logging.debug("InvalidPath raised when calling list_groups in tearDown...")
            group_ids = []
        for group_id in group_ids:
            logging.debug("Deleting group ID: %s" % group_id)
            self.client.secrets.identity.delete_group(
                group_id=group_id,
                mount_point=self.TEST_MOUNT_POINT,
            )

    @parameterized.expand(
        [
            param(
                "create success",
            ),
            param("create success with metadata", metadata=dict(something="meta")),
            param(
                "create failure with metadata",
                metadata="not a dict",
                raises=exceptions.ParamValidationError,
                exception_message="unsupported metadata argument provided",
            ),
            param(
                "update success",
                create_first=True,
            ),
        ]
    )
    def test_create_or_update_entity(
        self,
        label,
        metadata=None,
        create_first=False,
        raises=None,
        exception_message="",
    ):
        entity_id = None
        if create_first:
            create_first_response = (
                self.client.secrets.identity.create_or_update_entity(
                    name=self.TEST_ENTITY_NAME,
                    entity_id=entity_id,
                    metadata=metadata,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            )
            logging.debug("create_first_response: %s" % create_first_response)
            entity_id = create_first_response["data"]["id"]
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.identity.create_or_update_entity(
                    name=self.TEST_ENTITY_NAME,
                    metadata=metadata,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            create_or_update_response = (
                self.client.secrets.identity.create_or_update_entity(
                    name=self.TEST_ENTITY_NAME,
                    entity_id=entity_id,
                    metadata=metadata,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            )
            logging.debug("create_or_update_response: %s" % create_or_update_response)
            if isinstance(create_or_update_response, dict):
                self.assertIn(
                    member="id",
                    container=create_or_update_response["data"],
                )
                if entity_id is not None:
                    self.assertEqual(
                        first=entity_id,
                        second=create_or_update_response["data"]["id"],
                    )
            else:
                self.assertEqual(
                    first=bool(create_or_update_response),
                    second=True,
                )

    @parameterized.expand(
        [
            param(
                "create success",
            ),
            param("create success with metadata", metadata=dict(something="meta")),
            param(
                "create failure with metadata",
                metadata="not a dict",
                raises=exceptions.ParamValidationError,
                exception_message="unsupported metadata argument provided",
            ),
            param(
                "update success",
                create_first=True,
            ),
        ]
    )
    @skipIf(
        utils.vault_version_lt("0.11.2"), '"by name" operations added in Vault v0.11.2'
    )
    def test_create_or_update_entity_by_name(
        self,
        label,
        metadata=None,
        create_first=False,
        raises=None,
        exception_message="",
    ):
        entity_id = None
        if create_first:
            create_first_response = (
                self.client.secrets.identity.create_or_update_entity(
                    name=self.TEST_ENTITY_NAME,
                    entity_id=entity_id,
                    metadata=metadata,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            )
            logging.debug("create_first_response: %s" % create_first_response)
            entity_id = create_first_response["data"]["id"]
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.identity.create_or_update_entity_by_name(
                    name=self.TEST_ENTITY_NAME,
                    metadata=metadata,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            create_or_update_response = (
                self.client.secrets.identity.create_or_update_entity_by_name(
                    name=self.TEST_ENTITY_NAME,
                    metadata=metadata,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            )
            logging.debug("create_or_update_response: %s" % create_or_update_response)
            if not create_first:
                self.assertIn(
                    member="id",
                    container=create_or_update_response["data"],
                )
                if entity_id is not None:
                    self.assertEqual(
                        first=entity_id,
                        second=create_or_update_response["data"]["id"],
                    )
            else:
                self.assertEqual(
                    first=bool(create_or_update_response),
                    second=True,
                )

    @parameterized.expand(
        [
            param(
                "read success",
            ),
            param("read failure", create_first=False, raises=exceptions.InvalidPath),
        ]
    )
    def test_read_entity_by_id(
        self, label, create_first=True, raises=None, exception_message=""
    ):
        entity_id = None
        if create_first:
            create_first_response = (
                self.client.secrets.identity.create_or_update_entity(
                    name=self.TEST_ENTITY_NAME,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            )
            logging.debug("create_first_response: %s" % create_first_response)
            entity_id = create_first_response["data"]["id"]
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.identity.read_entity(
                    entity_id=entity_id,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            read_entity_by_id_response = self.client.secrets.identity.read_entity(
                entity_id=entity_id,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("read_entity_by_id_response: %s" % read_entity_by_id_response)
            self.assertEqual(
                first=entity_id,
                second=read_entity_by_id_response["data"]["id"],
            )

    @parameterized.expand(
        [
            param(
                "read success",
            ),
            param("read failure", create_first=False, raises=exceptions.InvalidPath),
        ]
    )
    @skipIf(
        utils.vault_version_lt("0.11.2"), '"by name" operations added in Vault v0.11.2'
    )
    def test_read_entity_by_name(
        self, label, create_first=True, raises=None, exception_message=""
    ):
        entity_id = None
        if create_first:
            create_first_response = (
                self.client.secrets.identity.create_or_update_entity(
                    name=self.TEST_ENTITY_NAME,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            )
            logging.debug("create_first_response: %s" % create_first_response)
            entity_id = create_first_response["data"]["id"]
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.identity.read_entity_by_name(
                    name=self.TEST_ENTITY_NAME,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            read_entity_by_name_response = (
                self.client.secrets.identity.read_entity_by_name(
                    name=self.TEST_ENTITY_NAME,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            )
            logging.debug(
                "read_entity_by_name_response: %s" % read_entity_by_name_response
            )
            self.assertEqual(
                first=entity_id,
                second=read_entity_by_name_response["data"]["id"],
            )

    @parameterized.expand(
        [
            param(
                "update success",
            ),
            param("update success with metadata", metadata=dict(something="meta")),
            param(
                "update failure with metadata",
                metadata="not a dict",
                raises=exceptions.ParamValidationError,
                exception_message="unsupported metadata argument provided",
            ),
        ]
    )
    def test_update_entity(
        self, label, metadata=None, raises=None, exception_message=""
    ):
        create_first_response = self.client.secrets.identity.create_or_update_entity(
            name=self.TEST_ENTITY_NAME,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug("create_first_response: %s" % create_first_response)
        entity_id = create_first_response["data"]["id"]
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.identity.update_entity(
                    entity_id=entity_id,
                    metadata=metadata,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            update_entity_response = self.client.secrets.identity.update_entity(
                entity_id=entity_id,
                metadata=metadata,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("update_entity_response: %s" % update_entity_response)
            if isinstance(update_entity_response, dict):
                self.assertEqual(
                    first=update_entity_response["data"]["id"],
                    second=entity_id,
                )
            else:
                self.assertEqual(
                    first=bool(update_entity_response),
                    second=True,
                )

    @parameterized.expand(
        [
            param(
                "delete success",
            ),
            param(
                "delete success with no corresponding entity",
                create_first=False,
            ),
        ]
    )
    def test_delete_entity_by_id(
        self, label, create_first=True, raises=None, exception_message=""
    ):
        entity_id = None
        if create_first:
            create_first_response = (
                self.client.secrets.identity.create_or_update_entity(
                    name=self.TEST_ENTITY_NAME,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            )
            logging.debug("create_first_response: %s" % create_first_response)
            entity_id = create_first_response["data"]["id"]
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.identity.delete_entity(
                    entity_id=entity_id,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            delete_entity_response = self.client.secrets.identity.delete_entity(
                entity_id=entity_id,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("update_entity_response: %s" % delete_entity_response)
            self.assertEqual(
                first=bool(delete_entity_response),
                second=True,
            )

    @parameterized.expand(
        [
            param(
                "delete success",
            ),
            param(
                "delete success with no corresponding entity",
                create_first=False,
            ),
        ]
    )
    @skipIf(
        utils.vault_version_lt("0.11.2"), '"by name" operations added in Vault v0.11.2'
    )
    def test_delete_entity_by_name(
        self, label, create_first=True, raises=None, exception_message=""
    ):
        if create_first:
            create_first_response = (
                self.client.secrets.identity.create_or_update_entity(
                    name=self.TEST_ENTITY_NAME,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            )
            logging.debug("create_first_response: %s" % create_first_response)
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.identity.delete_entity_by_name(
                    name=self.TEST_ENTITY_NAME,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            delete_entity_response = self.client.secrets.identity.delete_entity_by_name(
                name=self.TEST_ENTITY_NAME,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("update_entity_response: %s" % delete_entity_response)
            self.assertEqual(
                first=bool(delete_entity_response),
                second=True,
            )

    @parameterized.expand(
        [
            param(
                "list success - LIST method",
            ),
            param(
                "list success - GET method",
                method="GET",
            ),
            param(
                "list failure - invalid method",
                method="PUT",
                raises=exceptions.ParamValidationError,
                exception_message='"method" parameter provided invalid value',
            ),
        ]
    )
    def test_list_entities_by_id(
        self, label, method="LIST", raises=None, exception_message=""
    ):
        create_response = self.client.secrets.identity.create_or_update_entity(
            name=self.TEST_ENTITY_NAME,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug("create_response: %s" % create_response)
        entity_id = create_response["data"]["id"]
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.identity.list_entities(
                    method=method,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            list_entities_response = self.client.secrets.identity.list_entities(
                method=method,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("list_entities_response: %s" % list_entities_response)
            self.assertEqual(
                first=[entity_id],
                second=list_entities_response["data"]["keys"],
            )

    @parameterized.expand(
        [
            param(
                "list success - LIST method",
            ),
            param(
                "list success - GET method",
                method="GET",
            ),
            param(
                "list failure - invalid method",
                method="PUT",
                raises=exceptions.ParamValidationError,
                exception_message='"method" parameter provided invalid value',
            ),
        ]
    )
    @skipIf(
        utils.vault_version_lt("0.11.2"), '"by name" operations added in Vault v0.11.2'
    )
    def test_list_entities_by_name(
        self, label, method="LIST", raises=None, exception_message=""
    ):
        create_response = self.client.secrets.identity.create_or_update_entity(
            name=self.TEST_ENTITY_NAME,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug("create_response: %s" % create_response)
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.identity.list_entities_by_name(
                    method=method,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            list_entities_response = self.client.secrets.identity.list_entities_by_name(
                method=method,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("list_entities_response: %s" % list_entities_response)
            self.assertEqual(
                first=[self.TEST_ENTITY_NAME],
                second=list_entities_response["data"]["keys"],
            )

    @parameterized.expand(
        [
            param(
                "merge success",
            ),
            param(
                "merge failure",
            ),
        ]
    )
    def test_merge_entities(self, label, raises=None, exception_message=""):
        create_response = self.client.secrets.identity.create_or_update_entity(
            name=self.TEST_ENTITY_NAME,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug("create_response: %s" % create_response)
        create_response2 = self.client.secrets.identity.create_or_update_entity(
            name="%s2" % self.TEST_ENTITY_NAME,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug("create_response2: %s" % create_response2)
        to_entity_id = create_response["data"]["id"]
        from_entity_ids = [create_response2["data"]["id"]]
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.identity.merge_entities(
                    from_entity_ids=from_entity_ids,
                    to_entity_id=to_entity_id,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            merge_entities_response = self.client.secrets.identity.merge_entities(
                from_entity_ids=from_entity_ids,
                to_entity_id=to_entity_id,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("merge_entities_response: %s" % merge_entities_response)
            self.assertEqual(
                first=bool(merge_entities_response),
                second=True,
            )

    @parameterized.expand(
        [
            param(
                "merge success",
            ),
            param(
                "merge failure",
            ),
        ]
    )
    @skipIf(
        utils.vault_version_lt("1.12.0"),
        '"conflicting_alias_ids_to_keep" added in Vault v1.12.0',
    )
    def test_merge_entities_conflicting(self, label, raises=None, exception_message=""):
        create_response = self.client.secrets.identity.create_or_update_entity(
            name=self.TEST_ENTITY_NAME,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug("create_response: %s" % create_response)
        create_response2 = self.client.secrets.identity.create_or_update_entity(
            name="%s2" % self.TEST_ENTITY_NAME,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug("create_response2: %s" % create_response2)
        create_response3 = self.client.secrets.identity.create_or_update_entity(
            name="%s3" % self.TEST_ENTITY_NAME,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug("create_response3: %s" % create_response3)
        parent_id = create_response["data"]["id"]
        merge_id1 = create_response2["data"]["id"]
        merge_id2 = create_response3["data"]["id"]

        merge_entities_response = self.client.secrets.identity.merge_entities(
            from_entity_ids=[merge_id1],
            to_entity_id=parent_id,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug("merge_entities_response: %s" % merge_entities_response)

        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.identity.merge_entities(
                    from_entity_ids=merge_id2,
                    to_entity_id=parent_id,
                    mount_point=self.TEST_MOUNT_POINT,
                    conflicting_alias_ids_to_keep=[merge_id1],
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            merge_conflicting_entities_response = (
                self.client.secrets.identity.merge_entities(
                    from_entity_ids=merge_id2,
                    to_entity_id=parent_id,
                    mount_point=self.TEST_MOUNT_POINT,
                    conflicting_alias_ids_to_keep=[merge_id1],
                )
            )
            logging.debug(
                "merge_conflicting_entities_response: %s"
                % merge_conflicting_entities_response
            )
            self.assertEqual(
                first=bool(merge_conflicting_entities_response),
                second=True,
            )

    @parameterized.expand(
        [
            param(
                "create success",
            ),
            param(
                "update success",
                create_first=True,
            ),
        ]
    )
    def test_create_or_update_entity_alias(
        self, label, create_first=False, raises=None, exception_message=""
    ):
        entity_id = None
        if create_first:
            create_first_response = (
                self.client.secrets.identity.create_or_update_entity(
                    name=self.TEST_ENTITY_NAME,
                    entity_id=entity_id,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            )
            logging.debug("create_first_response: %s" % create_first_response)
            entity_id = create_first_response["data"]["id"]
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.identity.create_or_update_entity_alias(
                    name=self.TEST_ALIAS_NAME,
                    canonical_id=entity_id,
                    mount_accessor=self.test_approle_accessor,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            create_or_update_response = (
                self.client.secrets.identity.create_or_update_entity_alias(
                    name=self.TEST_ALIAS_NAME,
                    canonical_id=entity_id,
                    mount_accessor=self.test_approle_accessor,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            )
            logging.debug("create_or_update_response: %s" % create_or_update_response)

            self.assertIn(
                member="id",
                container=create_or_update_response["data"],
            )
            if entity_id is not None:
                self.assertEqual(
                    first=create_or_update_response["data"]["canonical_id"],
                    second=entity_id,
                )

    @parameterized.expand(
        [
            param(
                "read success",
            ),
            param(
                "read failure",
                create_first=False,
                raises=exceptions.InvalidPath,
            ),
        ]
    )
    def test_read_entity_alias_by_id(
        self, label, create_first=True, raises=None, exception_message=""
    ):
        alias_id = None
        if create_first:
            create_entity_first_response = (
                self.client.secrets.identity.create_or_update_entity(
                    name=self.TEST_ENTITY_NAME,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            )
            logging.debug(
                "create_entity_first_response: %s" % create_entity_first_response
            )
            entity_id = create_entity_first_response["data"]["id"]
            create_entity_alias_first_response = (
                self.client.secrets.identity.create_or_update_entity_alias(
                    name=self.TEST_ALIAS_NAME,
                    canonical_id=entity_id,
                    mount_accessor=self.test_approle_accessor,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            )
            logging.debug(
                "create_entity_alias_first_response: %s"
                % create_entity_alias_first_response
            )
            alias_id = create_entity_alias_first_response["data"]["id"]
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.identity.read_entity_alias(
                    alias_id=alias_id,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            read_entity_alias_response = self.client.secrets.identity.read_entity_alias(
                alias_id=alias_id,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("read_entity_alias_response: %s" % read_entity_alias_response)

            self.assertIn(
                member="id",
                container=read_entity_alias_response["data"],
            )
            if alias_id is not None:
                self.assertEqual(
                    first=read_entity_alias_response["data"]["id"],
                    second=alias_id,
                )

    @parameterized.expand(
        [
            param(
                "update success",
            ),
            param(
                "update failure with invalid mount accessor",
                mount_accessor="not a valid accessor",
                raises=exceptions.InvalidRequest,
                exception_message="invalid mount accessor",
            ),
        ]
    )
    def test_update_entity_alias_by_id(
        self, label, mount_accessor=None, raises=None, exception_message=""
    ):
        if mount_accessor is None:
            mount_accessor = self.test_approle_accessor
        create_entity_first_response = (
            self.client.secrets.identity.create_or_update_entity(
                name=self.TEST_ENTITY_NAME,
                mount_point=self.TEST_MOUNT_POINT,
            )
        )
        logging.debug("create_entity_first_response: %s" % create_entity_first_response)
        entity_id = create_entity_first_response["data"]["id"]
        create_entity_alias_first_response = (
            self.client.secrets.identity.create_or_update_entity_alias(
                name=self.TEST_ALIAS_NAME,
                canonical_id=entity_id,
                mount_accessor=self.test_approle_accessor,
                mount_point=self.TEST_MOUNT_POINT,
            )
        )
        logging.debug(
            "create_entity_alias_first_response: %s"
            % create_entity_alias_first_response
        )
        alias_id = create_entity_alias_first_response["data"]["id"]
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.identity.update_entity_alias(
                    alias_id=alias_id,
                    name=self.TEST_ALIAS_NAME,
                    canonical_id=entity_id,
                    mount_accessor=mount_accessor,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            update_entity_response = self.client.secrets.identity.update_entity_alias(
                alias_id=alias_id,
                name=self.TEST_ALIAS_NAME,
                canonical_id=entity_id,
                mount_accessor=mount_accessor,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("update_entity_response: %s" % update_entity_response)
            if isinstance(update_entity_response, dict):
                self.assertIn(
                    member="id",
                    container=update_entity_response["data"],
                )
                self.assertEqual(
                    first=update_entity_response["data"]["id"],
                    second=alias_id,
                )
            else:
                self.assertEqual(
                    first=bool(update_entity_response),
                    second=True,
                )

    @parameterized.expand(
        [
            param(
                "list success - LIST method",
            ),
            param(
                "list success - GET method",
                method="GET",
            ),
            param(
                "list failure - invalid method",
                method="PUT",
                raises=exceptions.ParamValidationError,
                exception_message='"method" parameter provided invalid value',
            ),
        ]
    )
    def test_list_entity_aliases_by_id(
        self, label, method="LIST", raises=None, exception_message=""
    ):
        create_response = self.client.secrets.identity.create_or_update_entity(
            name=self.TEST_ENTITY_NAME,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug("create_response: %s" % create_response)
        entity_id = create_response["data"]["id"]
        create_entity_alias_first_response = (
            self.client.secrets.identity.create_or_update_entity_alias(
                name=self.TEST_ALIAS_NAME,
                canonical_id=entity_id,
                mount_accessor=self.test_approle_accessor,
                mount_point=self.TEST_MOUNT_POINT,
            )
        )
        alias_id = create_entity_alias_first_response["data"]["id"]
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.identity.list_entity_aliases(
                    method=method,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            list_entities_response = self.client.secrets.identity.list_entity_aliases(
                method=method,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("list_entities_response: %s" % list_entities_response)
            self.assertEqual(
                first=[alias_id],
                second=list_entities_response["data"]["keys"],
            )

    @parameterized.expand(
        [
            param(
                "delete success",
            ),
            param(
                "delete success with no corresponding entity",
                create_first=False,
            ),
        ]
    )
    def test_delete_entity_alias_by_id(
        self, label, create_first=True, raises=None, exception_message=""
    ):
        alias_id = None
        if create_first:
            create_first_response = (
                self.client.secrets.identity.create_or_update_entity(
                    name=self.TEST_ENTITY_NAME,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            )
            logging.debug("create_first_response: %s" % create_first_response)
            entity_id = create_first_response["data"]["id"]
            create_entity_alias_first_response = (
                self.client.secrets.identity.create_or_update_entity_alias(
                    name=self.TEST_ALIAS_NAME,
                    canonical_id=entity_id,
                    mount_accessor=self.test_approle_accessor,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            )
            alias_id = create_entity_alias_first_response["data"]["id"]
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.identity.delete_entity_alias(
                    alias_id=alias_id,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            delete_entity_response = self.client.secrets.identity.delete_entity_alias(
                alias_id=alias_id,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("update_entity_response: %s" % delete_entity_response)
            self.assertEqual(
                first=bool(delete_entity_response),
                second=True,
            )

    @parameterized.expand(
        [
            param(
                "create success",
            ),
            param("create success with metadata", metadata=dict(something="meta")),
            param(
                "create failure with metadata",
                metadata="not a dict",
                raises=exceptions.ParamValidationError,
                exception_message="unsupported metadata argument provided",
            ),
            param(
                "create success with group type",
                group_type="external",
                add_members=False,
            ),
            param(
                "create failure with invalid group type",
                group_type="cosmic",
                raises=exceptions.ParamValidationError,
                exception_message='unsupported group_type argument provided "cosmic"',
            ),
            param(
                "update success",
                create_first=True,
            ),
        ]
    )
    def test_create_or_update_group(
        self,
        label,
        metadata=None,
        group_type="internal",
        create_first=False,
        add_members=True,
        raises=None,
        exception_message="",
    ):
        group_id = None
        member_entity_ids = None
        member_group_ids = None
        if add_members:
            create_entity_response = (
                self.client.secrets.identity.create_or_update_entity(
                    name=self.TEST_ENTITY_NAME,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            )
            logging.debug("create_entity_response: %s" % create_entity_response)
            member_entity_ids = [create_entity_response["data"]["id"]]
            create_member_group = self.client.secrets.identity.create_or_update_group(
                name=self.TEST_MEMBER_GROUP_NAME,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("create_member_group: %s" % create_member_group)
            member_group_ids = [create_member_group["data"]["id"]]
        if create_first:
            create_first_response = self.client.secrets.identity.create_or_update_group(
                name=self.TEST_GROUP_NAME,
                group_type=group_type,
                metadata=metadata,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("create_first_response: %s" % create_first_response)
            group_id = create_first_response["data"]["id"]
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.identity.create_or_update_group(
                    name=self.TEST_GROUP_NAME,
                    group_id=group_id,
                    group_type=group_type,
                    metadata=metadata,
                    member_group_ids=member_group_ids,
                    member_entity_ids=member_entity_ids,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            create_or_update_response = (
                self.client.secrets.identity.create_or_update_group(
                    name=self.TEST_GROUP_NAME,
                    group_id=group_id,
                    group_type=group_type,
                    metadata=metadata,
                    member_group_ids=member_group_ids,
                    member_entity_ids=member_entity_ids,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            )
            logging.debug("create_or_update_response: %s" % create_or_update_response)
            if isinstance(create_or_update_response, dict):
                self.assertIn(
                    member="id",
                    container=create_or_update_response["data"],
                )
                if group_id is not None:
                    self.assertEqual(
                        first=group_id,
                        second=create_or_update_response["data"]["id"],
                    )
                read_group_response = self.client.secrets.identity.read_group(
                    group_id=create_or_update_response["data"]["id"],
                    mount_point=self.TEST_MOUNT_POINT,
                )
                logging.debug("read_group_response: %s" % read_group_response)
                self.assertEqual(
                    first=read_group_response["data"]["member_group_ids"],
                    second=member_group_ids,
                )
                expected_member_entity_ids = (
                    member_entity_ids
                    if member_entity_ids is not None
                    else []
                    if group_type == "external"
                    and (
                        utils.vault_version_lt("1.9.9")
                    )  # https://github.com/hashicorp/vault/pull/16088
                    else None
                )
                self.assertEqual(
                    first=read_group_response["data"]["member_entity_ids"],
                    second=expected_member_entity_ids,
                )
            else:
                self.assertEqual(
                    first=bool(create_or_update_response),
                    second=True,
                )

    @parameterized.expand(
        [
            param(
                "update success",
            ),
            param("update success with metadata", metadata=dict(something="meta")),
            param(
                "update failure with metadata",
                metadata="not a dict",
                raises=exceptions.ParamValidationError,
                exception_message="unsupported metadata argument provided",
            ),
            param(
                "update failure with changed group type",
                group_type="external",
                raises=exceptions.InvalidRequest,
                exception_message="group type cannot be changed",
            ),
            param(
                "update failure with invalid group type",
                group_type="cosmic",
                raises=exceptions.ParamValidationError,
                exception_message='unsupported group_type argument provided "cosmic"',
            ),
            param(
                "update success",
                create_first=True,
            ),
        ]
    )
    def test_update_group_by_id(
        self,
        label,
        metadata=None,
        group_type="internal",
        create_first=True,
        update_members=True,
        raises=None,
        exception_message="",
    ):
        group_id = None
        member_entity_ids = None
        member_group_ids = None
        if update_members:
            create_entity_response = (
                self.client.secrets.identity.create_or_update_entity(
                    name=self.TEST_ENTITY_NAME,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            )
            logging.debug("create_entity_response: %s" % create_entity_response)
            member_entity_ids = [create_entity_response["data"]["id"]]
            create_member_group = self.client.secrets.identity.create_or_update_group(
                name=self.TEST_MEMBER_GROUP_NAME,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("create_member_group: %s" % create_member_group)
            member_group_ids = [create_member_group["data"]["id"]]
        if create_first:
            create_first_response = self.client.secrets.identity.create_or_update_group(
                name=self.TEST_GROUP_NAME,
                group_type="internal",
                metadata=None,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("create_first_response: %s" % create_first_response)
            group_id = create_first_response["data"]["id"]
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.identity.update_group(
                    name=self.TEST_GROUP_NAME,
                    group_id=group_id,
                    group_type=group_type,
                    metadata=metadata,
                    member_group_ids=member_group_ids,
                    member_entity_ids=member_entity_ids,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            update_response = self.client.secrets.identity.update_group(
                name=self.TEST_GROUP_NAME,
                group_id=group_id,
                group_type=group_type,
                metadata=metadata,
                member_group_ids=member_group_ids,
                member_entity_ids=member_entity_ids,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("update_response: %s" % update_response)

            if isinstance(update_response, dict):
                self.assertEqual(
                    first=update_response["data"]["id"],
                    second=group_id,
                )
            else:
                self.assertEqual(
                    first=bool(update_response),
                    second=True,
                )
            read_group_response = self.client.secrets.identity.read_group(
                group_id=group_id,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("read_group_response: %s" % read_group_response)
            self.assertEqual(
                first=read_group_response["data"]["member_group_ids"],
                second=member_group_ids,
            )
            expected_member_entity_ids = (
                member_entity_ids if member_entity_ids is not None else []
            )
            self.assertEqual(
                first=read_group_response["data"]["member_entity_ids"],
                second=expected_member_entity_ids,
            )

    @parameterized.expand(
        [
            param(
                "list success - LIST method",
            ),
            param(
                "list success - GET method",
                method="GET",
            ),
            param(
                "list failure - invalid method",
                method="PUT",
                raises=exceptions.ParamValidationError,
                exception_message='"method" parameter provided invalid value',
            ),
        ]
    )
    @skipIf(
        utils.vault_version_lt("0.11.2"), '"by name" operations added in Vault v0.11.2'
    )
    def test_list_groups_by_name(
        self, label, method="LIST", raises=None, exception_message=""
    ):
        create_response = self.client.secrets.identity.create_or_update_group(
            name=self.TEST_GROUP_NAME,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug("create_response: %s" % create_response)
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.identity.list_groups_by_name(
                    method=method,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            list_groups_response = self.client.secrets.identity.list_groups_by_name(
                method=method,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("list_groups_response: %s" % list_groups_response)
            self.assertEqual(
                first=[self.TEST_GROUP_NAME],
                second=list_groups_response["data"]["keys"],
            )

    @parameterized.expand(
        [
            param(
                "update success",
            ),
            param("update success with metadata", metadata=dict(something="meta")),
            param(
                "update failure with metadata",
                metadata="not a dict",
                raises=exceptions.ParamValidationError,
                exception_message="unsupported metadata argument provided",
            ),
            param(
                "update failure with changed group type",
                group_type="external",
                raises=exceptions.InvalidRequest,
                exception_message="group type cannot be changed",
            ),
            param(
                "update failure with invalid group type",
                group_type="cosmic",
                raises=exceptions.ParamValidationError,
                exception_message='unsupported group_type argument provided "cosmic"',
            ),
            param(
                "update success",
                create_first=True,
            ),
        ]
    )
    @skipIf(
        utils.vault_version_lt("0.11.2"), '"by name" operations added in Vault v0.11.2'
    )
    def test_create_or_update_group_by_name(
        self,
        label,
        metadata=None,
        group_type="internal",
        create_first=True,
        raises=None,
        exception_message="",
    ):
        if create_first:
            create_first_response = self.client.secrets.identity.create_or_update_group(
                name=self.TEST_GROUP_NAME,
                group_type="internal",
                metadata=None,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("create_first_response: %s" % create_first_response)
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.identity.create_or_update_group_by_name(
                    name=self.TEST_GROUP_NAME,
                    group_type=group_type,
                    metadata=metadata,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            update_response = (
                self.client.secrets.identity.create_or_update_group_by_name(
                    name=self.TEST_GROUP_NAME,
                    group_type=group_type,
                    metadata=metadata,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            )
            logging.debug("update_response: %s" % update_response)
            self.assertEqual(
                first=bool(update_response),
                second=True,
            )

    @parameterized.expand(
        [
            param(
                "read success",
            ),
            param("read failure", create_first=False, raises=exceptions.InvalidPath),
        ]
    )
    @skipIf(
        utils.vault_version_lt("0.11.2"), '"by name" operations added in Vault v0.11.2'
    )
    def test_read_group_by_name(
        self, label, create_first=True, raises=None, exception_message=""
    ):
        group_id = None
        if create_first:
            create_first_response = self.client.secrets.identity.create_or_update_group(
                name=self.TEST_GROUP_NAME,
                group_type="internal",
                metadata=None,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("create_first_response: %s" % create_first_response)
            group_id = create_first_response["data"]["id"]
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.identity.read_entity_by_name(
                    name=self.TEST_GROUP_NAME,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            read_group_response = self.client.secrets.identity.read_group_by_name(
                name=self.TEST_GROUP_NAME,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("read_group_response: %s" % read_group_response)
            self.assertEqual(
                first=group_id,
                second=read_group_response["data"]["id"],
            )

    @parameterized.expand(
        [
            param(
                "create success",
            ),
            param(
                "update success",
                create_first=True,
            ),
        ]
    )
    def test_create_or_update_group_alias(
        self, label, create_first=False, raises=None, exception_message=""
    ):
        alias_id = None
        create_first_response = self.client.secrets.identity.create_or_update_group(
            name=self.TEST_ENTITY_NAME,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug("create_first_response: %s" % create_first_response)
        if create_first:
            create_alias_response = (
                self.client.secrets.identity.create_or_update_group_alias(
                    name=self.TEST_GROUP_NAME,
                    mount_accessor=self.test_approle_accessor,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            )
            logging.debug("create_alias_response: %s" % create_alias_response)
            alias_id = create_alias_response["data"]["id"]
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.identity.create_or_update_group_alias(
                    name=self.TEST_ENTITY_NAME,
                    alias_id=alias_id,
                    mount_accessor=self.test_approle_accessor,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            create_or_update_response = (
                self.client.secrets.identity.create_or_update_group_alias(
                    name=self.TEST_GROUP_NAME,
                    alias_id=alias_id,
                    mount_accessor=self.test_approle_accessor,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            )
            logging.debug("create_or_update_response: %s" % create_or_update_response)
            if "data" in create_or_update_response:
                self.assertIn(
                    member="id",
                    container=create_or_update_response["data"],
                )
                if alias_id is not None:
                    self.assertEqual(
                        first=alias_id,
                        second=create_or_update_response["data"]["id"],
                    )
            else:
                self.assertEqual(
                    first=create_or_update_response.status_code,
                    second=204,
                )

    @parameterized.expand(
        [
            param(
                "read success",
            ),
            param(
                "read failure",
                create_first=False,
                raises=exceptions.InvalidPath,
            ),
        ]
    )
    def test_read_group_alias(
        self, label, create_first=True, raises=None, exception_message=""
    ):
        alias_id = None
        create_first_response = self.client.secrets.identity.create_or_update_group(
            name=self.TEST_ENTITY_NAME,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug("create_first_response: %s" % create_first_response)
        if create_first:
            create_alias_response = (
                self.client.secrets.identity.create_or_update_group_alias(
                    name=self.TEST_GROUP_NAME,
                    mount_accessor=self.test_approle_accessor,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            )
            logging.debug("create_alias_response: %s" % create_alias_response)
            alias_id = create_alias_response["data"]["id"]
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.identity.read_group_alias(
                    alias_id=alias_id,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            read_group_alias_response = self.client.secrets.identity.read_group_alias(
                alias_id=alias_id,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("read_group_alias_response: %s" % read_group_alias_response)

            self.assertIn(
                member="id",
                container=read_group_alias_response["data"],
            )
            if alias_id is not None:
                self.assertEqual(
                    first=read_group_alias_response["data"]["id"],
                    second=alias_id,
                )

    @parameterized.expand(
        [
            param(
                "list success - LIST method",
            ),
            param(
                "list success - GET method",
                method="GET",
            ),
            param(
                "list failure - invalid method",
                method="PUT",
                raises=exceptions.ParamValidationError,
                exception_message='"method" parameter provided invalid value',
            ),
        ]
    )
    def test_list_group_aliases(
        self, label, method="LIST", raises=None, exception_message=""
    ):
        create_group_response = self.client.secrets.identity.create_or_update_group(
            name=self.TEST_GROUP_ALIAS_NAME,
            group_type="internal",
            metadata=None,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug("create_group_response: %s" % create_group_response)
        create_alias_response = (
            self.client.secrets.identity.create_or_update_group_alias(
                name=self.TEST_GROUP_NAME,
                mount_accessor=self.test_approle_accessor,
                mount_point=self.TEST_MOUNT_POINT,
            )
        )
        logging.debug("create_alias_response: %s" % create_alias_response)
        alias_id = create_alias_response["data"]["id"]
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.identity.list_group_aliases(
                    method=method,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            list_groups_response = self.client.secrets.identity.list_group_aliases(
                method=method,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("list_groups_response: %s" % list_groups_response)
            self.assertEqual(
                first=[alias_id],
                second=list_groups_response["data"]["keys"],
            )

    @parameterized.expand(
        [
            param(
                "lookup entity",
                criteria=["entity_id"],
            ),
            param(
                "lookup entity alias",
                criteria=["alias_id"],
            ),
            param(
                "lookup missing entity",
                criteria=["entity_id"],
                create_first=False,
            ),
        ]
    )
    def test_lookup_entity(
        self, label, criteria, create_first=True, raises=None, exception_message=""
    ):
        lookup_params = {}
        if create_first:
            create_entity_response = (
                self.client.secrets.identity.create_or_update_entity(
                    name=self.TEST_ENTITY_NAME,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            )
            logging.debug("create_entity_response: %s" % create_entity_response)
            entity_id = create_entity_response["data"]["id"]
            create_alias_response = (
                self.client.secrets.identity.create_or_update_entity_alias(
                    name=self.TEST_ALIAS_NAME,
                    canonical_id=entity_id,
                    mount_accessor=self.test_approle_accessor,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            )
            logging.debug("create_alias_response: %s" % create_alias_response)
            alias_id = create_alias_response["data"]["id"]
            if "entity_id" in criteria:
                lookup_params["entity_id"] = entity_id
            elif "alias_id" in criteria:
                lookup_params["alias_id"] = alias_id
        else:
            for key in criteria:
                lookup_params[key] = key
        logging.debug("lookup_params: %s" % lookup_params)
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.identity.lookup_entity(
                    mount_point=self.TEST_MOUNT_POINT, **lookup_params
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            lookup_entity_response = self.client.secrets.identity.lookup_entity(
                mount_point=self.TEST_MOUNT_POINT, **lookup_params
            )
            logging.debug("lookup_entity_response: %s" % lookup_entity_response)
            if create_first:
                if "entity_id" in criteria:
                    self.assertEqual(
                        first=lookup_entity_response["data"]["name"],
                        second=self.TEST_ENTITY_NAME,
                    )
                elif "alias_id" in criteria:
                    self.assertEqual(
                        first=lookup_entity_response["data"]["aliases"][0]["name"],
                        second=self.TEST_ALIAS_NAME,
                    )
            else:
                self.assertEqual(
                    first=lookup_entity_response.status_code,
                    second=204,
                )

    @parameterized.expand(
        [
            param(
                "lookup group",
                criteria=["group_id"],
            ),
            param(
                "lookup group alias",
                criteria=["alias_id"],
            ),
            param(
                "lookup name",
                criteria=["name"],
            ),
            param(
                "lookup alias",
                criteria=["alias_name", "alias_mount_accessor"],
            ),
            param(
                "lookup missing group",
                criteria=["group_id"],
                create_first=False,
            ),
        ]
    )
    def test_lookup_group(
        self, label, criteria, create_first=True, raises=None, exception_message=""
    ):
        lookup_params = {}
        if create_first:
            create_group_response = self.client.secrets.identity.create_or_update_group(
                name=self.TEST_GROUP_NAME,
                group_type="external",
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("create_group_response: %s" % create_group_response)
            group_id = create_group_response["data"]["id"]
            create_alias_response = (
                self.client.secrets.identity.create_or_update_group_alias(
                    name=self.TEST_GROUP_ALIAS_NAME,
                    canonical_id=group_id,
                    mount_accessor=self.test_approle_accessor,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            )
            logging.debug("create_alias_response: %s" % create_alias_response)
            alias_id = create_alias_response["data"]["id"]
            if "group_id" in criteria:
                lookup_params["group_id"] = group_id
            elif "alias_id" in criteria:
                lookup_params["alias_id"] = alias_id
            elif "name" in criteria:
                lookup_params["name"] = self.TEST_GROUP_NAME
            elif "alias_name" in criteria and "alias_mount_accessor" in criteria:
                lookup_params["alias_name"] = self.TEST_GROUP_ALIAS_NAME
                lookup_params["alias_mount_accessor"] = self.test_approle_accessor
        else:
            for key in criteria:
                lookup_params[key] = key
        logging.debug("lookup_params: %s" % lookup_params)
        if raises:
            with self.assertRaises(raises) as cm:
                self.client.secrets.identity.lookup_group(
                    mount_point=self.TEST_MOUNT_POINT, **lookup_params
                )
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            lookup_group_response = self.client.secrets.identity.lookup_group(
                mount_point=self.TEST_MOUNT_POINT, **lookup_params
            )
            logging.debug("lookup_group_response: %s" % lookup_group_response)
            if create_first:
                if "group_id" in criteria or "name" in criteria:
                    self.assertEqual(
                        first=lookup_group_response["data"]["name"],
                        second=self.TEST_GROUP_NAME,
                    )
                elif "alias_id" in criteria or (
                    "alias_name" in criteria and "alias_mount_accessor" in criteria
                ):
                    self.assertEqual(
                        first=lookup_group_response["data"]["alias"]["name"],
                        second=self.TEST_GROUP_ALIAS_NAME,
                    )
            else:
                self.assertEqual(
                    first=lookup_group_response.status_code,
                    second=204,
                )

    @parameterized.expand(
        [
            param(
                "empty issuer",
                issuer="",
            ),
            param(
                "issuer set",
                issuer="https://python-hvac.org:1234",
            ),
        ]
    )
    def test_configure_tokens_backend(self, label, issuer):
        response = self.client.secrets.identity.configure_tokens_backend(
            issuer=issuer,
        )
        logging.debug("configure_tokens_backend response: %s" % response)
        if issuer:
            # e.g.: 'warnings': ['If "issuer" is set explicitly, [...]']
            self.assertGreaterEqual(
                a=len(response["warnings"]),
                b=1,
            )
        else:
            # No response body if we're _not_ setting the issue
            self.assertEqual(
                first=204,
                second=response.status_code,
            )

    @parameterized.expand(
        [
            param(
                "empty issuer",
                issuer="",
            ),
            param(
                "issuer set",
                issuer="",
            ),
        ]
    )
    def test_read_tokens_backend_configuration(self, label, issuer):
        configure_tokens_backend_response = (
            self.client.secrets.identity.configure_tokens_backend(
                issuer=issuer,
            )
        )
        logging.debug(
            "configure_tokens_backend_response: %s" % configure_tokens_backend_response
        )
        response = self.client.secrets.identity.read_tokens_backend_configuration()
        logging.debug("read_tokens_backend_configuration response: %s" % response)
        self.assertEqual(
            first=issuer,
            second=response["data"]["issuer"],
        )

    @parameterized.expand(
        [
            param(
                "name set",
                name="hvac",
            ),
        ]
    )
    def test_create_named_key(self, label, name):
        response = self.client.secrets.identity.create_named_key(
            name=name,
        )
        logging.debug("create_named_key response: %s" % response)
        self.assertEqual(
            first=204,
            second=response.status_code,
        )

    @parameterized.expand(
        [
            param(
                "success",
                name="hvac",
                algorithm="ES256",
            ),
        ]
    )
    def test_read_named_key(self, label, name, algorithm):
        create_named_key_response = self.client.secrets.identity.create_named_key(
            name=name,
            algorithm=algorithm,
        )
        logging.debug("create_named_key response: %s" % create_named_key_response)
        response = self.client.secrets.identity.read_named_key(
            name=name,
        )
        logging.debug("read_named_key response: %s" % response)
        self.assertEqual(
            first=algorithm,
            second=response["data"]["algorithm"],
        )

    @parameterized.expand(
        [
            param(
                "success",
                name="hvac",
            ),
        ]
    )
    def test_delete_named_key(self, label, name):
        create_named_key_response = self.client.secrets.identity.create_named_key(
            name=name,
        )
        logging.debug("create_named_key response: %s" % create_named_key_response)
        response = self.client.secrets.identity.delete_named_key(
            name=name,
        )
        logging.debug("delete_named_key response: %s" % response)
        self.assertEqual(
            first=204,
            second=response.status_code,
        )

    @parameterized.expand(
        [
            param(
                "success",
                name="hvac",
            ),
        ]
    )
    def test_list_named_keys(self, label, name):
        create_named_key_response = self.client.secrets.identity.create_named_key(
            name=name,
        )
        logging.debug("create_named_key response: %s" % create_named_key_response)
        response = self.client.secrets.identity.list_named_keys()
        logging.debug("list_named_keys response: %s" % response)
        self.assertIn(
            member=name,
            container=response["data"]["keys"],
        )

    @parameterized.expand(
        [
            param(
                "lower ttl than at create time",
                name="hvac",
                verification_ttl=1800,
            ),
        ]
    )
    def test_rotate_named_key(self, label, name, verification_ttl):
        create_named_key_response = self.client.secrets.identity.create_named_key(
            name=name,
            verification_ttl=verification_ttl + 1,
        )
        logging.debug("create_named_key response: %s" % create_named_key_response)
        response = self.client.secrets.identity.rotate_named_key(
            name=name,
            verification_ttl=verification_ttl,
        )
        logging.debug("rotate_named_key response: %s" % response)
        self.assertEqual(
            first=204,
            second=response.status_code,
        )
        post_rotate_read_response = self.client.secrets.identity.read_named_key(
            name=name,
        )
        logging.debug(
            "post_rotate_read_response response: %s" % post_rotate_read_response
        )
        self.assertEqual(
            first=verification_ttl,
            second=post_rotate_read_response["data"]["verification_ttl"],
        )

    @parameterized.expand(
        [
            param(
                "success",
                name="hvac",
                key_name="hvac_key",
            ),
        ]
    )
    def test_create_or_update_role(self, label, name, key_name):
        create_named_key_response = self.client.secrets.identity.create_named_key(
            name=key_name,
        )
        logging.debug("create_named_key response: %s" % create_named_key_response)
        response = self.client.secrets.identity.create_or_update_role(
            name=name,
            key=key_name,
        )
        logging.debug("create_or_update_role response: %s" % response)
        self.assertEqual(
            first=204,
            second=response.status_code,
        )

    @parameterized.expand(
        [
            param(
                "success",
                name="hvac",
                key_name="hvac_key",
            ),
        ]
    )
    def test_read_role(self, label, name, key_name):
        create_named_key_response = self.client.secrets.identity.create_named_key(
            name=key_name,
        )
        logging.debug("create_named_key response: %s" % create_named_key_response)
        create_or_update_role_response = (
            self.client.secrets.identity.create_or_update_role(
                name=name,
                key=key_name,
            )
        )
        logging.debug(
            "create_or_update_role response: %s" % create_or_update_role_response
        )
        response = self.client.secrets.identity.read_role(
            name=name,
        )
        logging.debug("read_role response: %s" % response)
        self.assertEqual(
            first=key_name,
            second=response["data"]["key"],
        )

    @parameterized.expand(
        [
            param(
                "success",
                name="hvac",
                key_name="hvac_key",
            ),
        ]
    )
    def test_delete_role(self, label, name, key_name):
        create_named_key_response = self.client.secrets.identity.create_named_key(
            name=key_name,
        )
        logging.debug("create_named_key response: %s" % create_named_key_response)
        create_or_update_role_response = (
            self.client.secrets.identity.create_or_update_role(
                name=name,
                key=key_name,
            )
        )
        logging.debug(
            "create_or_update_role response: %s" % create_or_update_role_response
        )
        response = self.client.secrets.identity.delete_role(
            name=name,
        )
        logging.debug("delete_role response: %s" % response)
        self.assertEqual(
            first=204,
            second=response.status_code,
        )

    @parameterized.expand(
        [
            param(
                "success",
                name="hvac",
                key_name="hvac_key",
            ),
        ]
    )
    def test_list_roles(self, label, name, key_name):
        create_named_key_response = self.client.secrets.identity.create_named_key(
            name=key_name,
        )
        logging.debug("create_named_key response: %s" % create_named_key_response)
        create_or_update_role_response = (
            self.client.secrets.identity.create_or_update_role(
                name=name,
                key=key_name,
            )
        )
        logging.debug(
            "create_or_update_role response: %s" % create_or_update_role_response
        )
        response = self.client.secrets.identity.list_roles()
        logging.debug("list_roles response: %s" % response)
        self.assertIn(
            member=name,
            container=response["data"]["keys"],
        )

    @parameterized.expand(
        [
            param(
                "success",
                role_name="hvac",
                key_name="hvac_key",
            ),
        ]
    )
    def test_generate_signed_id_token(self, label, role_name, key_name):
        create_or_update_role_response = (
            self.client.secrets.identity.create_or_update_role(
                name=role_name,
                key=key_name,
            )
        )
        logging.debug(
            "create_or_update_role response: %s" % create_or_update_role_response
        )
        read_role_response = self.client.secrets.identity.read_role(
            name=role_name,
        )
        logging.debug("read_role response: %s" % read_role_response)
        token_client_id = read_role_response["data"]["client_id"]
        create_named_key_response = self.client.secrets.identity.create_named_key(
            name=key_name,
            allowed_client_ids=[
                token_client_id,
            ],
        )
        logging.debug("create_named_key response: %s" % create_named_key_response)
        # Log in using a dummy approle role so our client token has an associated identity
        self.login_using_admin_approle_role(
            role_id=self.TEST_APPROLE_ROLE_ID,
            path=self.TEST_APPROLE_PATH,
        )
        response = self.client.secrets.identity.generate_signed_id_token(
            name=role_name,
        )
        logging.debug("generate_signed_id_token response: %s" % response)
        self.assertIn(
            member=token_client_id,
            container=response["data"]["client_id"],
        )

    @parameterized.expand(
        [
            param(
                "success",
                role_name="hvac",
                key_name="hvac_key",
            ),
        ]
    )
    def test_introspect_signed_id_token(self, label, role_name, key_name):
        create_or_update_role_response = (
            self.client.secrets.identity.create_or_update_role(
                name=role_name,
                key=key_name,
            )
        )
        logging.debug(
            "create_or_update_role response: %s" % create_or_update_role_response
        )
        read_role_response = self.client.secrets.identity.read_role(
            name=role_name,
        )
        logging.debug("read_role response: %s" % read_role_response)
        token_client_id = read_role_response["data"]["client_id"]
        create_named_key_response = self.client.secrets.identity.create_named_key(
            name=key_name,
            allowed_client_ids=[
                token_client_id,
            ],
        )
        logging.debug("create_named_key response: %s" % create_named_key_response)
        # Log in using a dummy approle role so our client token has an associated identity
        self.login_using_admin_approle_role(
            role_id=self.TEST_APPROLE_ROLE_ID,
            path=self.TEST_APPROLE_PATH,
        )
        generate_signed_id_token_response = (
            self.client.secrets.identity.generate_signed_id_token(
                name=role_name,
            )
        )
        logging.debug(
            "generate_signed_id_token response: %s" % generate_signed_id_token_response
        )
        response = self.client.secrets.identity.introspect_signed_id_token(
            token=generate_signed_id_token_response["data"]["token"],
            client_id=token_client_id,
        )
        logging.debug("introspect_signed_id_token response: %s" % response)
        self.assertIn(
            member="active",
            container=response,
        )
        self.assertTrue(
            expr=response["active"],
        )

    @parameterized.expand(
        [
            param(
                "issuer set",
                issuer="https://python-hvac.org:1234",
            ),
        ]
    )
    def test_read_well_known_configurations(self, label, issuer):
        response = self.client.secrets.identity.configure_tokens_backend(
            issuer=issuer,
        )
        response = self.client.secrets.identity.read_well_known_configurations()
        logging.debug("read_well_known_configurations response: %s" % response)
        self.assertIn(
            member=issuer,
            container=response["issuer"],
        )

    @parameterized.expand(
        [
            param(
                "success",
                issuer="https://python-hvac.org:1234",
            ),
        ]
    )
    def test_read_active_public_keys(self, label, issuer):
        response = self.client.secrets.identity.configure_tokens_backend(
            issuer=issuer,
        )
        response = self.client.secrets.identity.read_active_public_keys()
        logging.debug("read_active_public_keys response: %s" % response)
        self.assertIn(
            member="keys",
            container=response,
        )
