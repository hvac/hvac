import logging
from unittest import TestCase, skipIf

from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


@skipIf(
    utils.vault_version_lt("1.4.0") or not utils.is_enterprise(),
    "Transform secrets engine only supported with Enterprise Vault",
)
class TestTransform(HvacIntegrationTestCase, TestCase):
    TEST_MOUNT_POINT = "transform-integration-test"

    def setUp(self):
        super().setUp()
        self.client.sys.enable_secrets_engine(
            backend_type="transform",
            path=self.TEST_MOUNT_POINT,
        )

    def tearDown(self):
        self.client.sys.disable_secrets_engine(path=self.TEST_MOUNT_POINT)
        super().tearDown()

    def test_create_or_update_role(self):
        create_response = self.client.secrets.transform.create_or_update_role(
            name="test_role",
            transformations=[
                "creditcard-fpe",
                "creditcard-masking",
            ],
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"create_response: {create_response}")
        self.assertEqual(
            first=create_response.status_code,
            second=204,
        )

    def test_read_role(self):
        transformations = [
            "creditcard-fpe",
            "creditcard-masking",
        ]
        create_response = self.client.secrets.transform.create_or_update_role(
            name="test_role",
            transformations=transformations,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"create_response: {create_response}")
        read_response = self.client.secrets.transform.read_role(
            name="test_role",
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"read_response: {read_response}")
        self.assertEqual(
            first=read_response["data"]["transformations"],
            second=transformations,
        )

    def test_list_roles(self):
        role_name = "test_role"
        transformations = [
            "creditcard-fpe",
            "creditcard-masking",
        ]
        create_response = self.client.secrets.transform.create_or_update_role(
            name=role_name,
            transformations=transformations,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"create_response: {create_response}")
        list_roles_response = self.client.secrets.transform.list_roles(
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"list_roles_response: {list_roles_response}")
        self.assertEqual(
            first=list_roles_response["data"]["keys"],
            second=[role_name],
        )

    def test_delete_role(self):
        role_name = "test_role"
        transformations = [
            "creditcard-fpe",
            "creditcard-masking",
        ]
        create_response = self.client.secrets.transform.create_or_update_role(
            name=role_name,
            transformations=transformations,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"create_response: {create_response}")
        create_response = self.client.secrets.transform.create_or_update_role(
            name="other-role",
            transformations=transformations,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"create_response: {create_response}")
        list_roles_response = self.client.secrets.transform.list_roles(
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"list_roles_response: {list_roles_response}")
        self.assertIn(
            member=role_name,
            container=list_roles_response["data"]["keys"],
        )
        delete_role_response = self.client.secrets.transform.delete_role(
            name=role_name,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"delete_role_response: {delete_role_response}")
        self.assertEqual(
            first=delete_role_response.status_code,
            second=204,
        )
        list_roles_response = self.client.secrets.transform.list_roles(
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"list_roles_response: {list_roles_response}")
        self.assertNotIn(
            member=role_name,
            container=list_roles_response["data"]["keys"],
        )

    def test_create_or_update_transformation(self):
        create_response = self.client.secrets.transform.create_or_update_transformation(
            name="test-transformation",
            transform_type="fpe",
            template="builtin/creditcardnumber",
            tweak_source="internal",
            allowed_roles=["test-role"],
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"create_response: {create_response}")
        self.assertEqual(
            first=create_response.status_code,
            second=204,
        )

    @skipIf(
        utils.vault_version_lt("1.7.0"),
        "Expanded tokenization support added in Vault version v1.7.0",
    )
    def test_create_or_update_fpe_transformation(self):
        create_response = (
            self.client.secrets.transform.create_or_update_fpe_transformation(
                name="test-transformation",
                template="builtin/creditcardnumber",
                tweak_source="internal",
                allowed_roles=["test-role"],
                mount_point=self.TEST_MOUNT_POINT,
            )
        )
        logging.debug(f"create_response: {create_response}")
        self.assertEqual(
            first=create_response.status_code,
            second=204,
        )

    @skipIf(
        utils.vault_version_lt("1.7.0"),
        "Expanded tokenization support added in Vault version v1.7.0",
    )
    def test_create_or_update_masking_transformation(self):
        create_response = (
            self.client.secrets.transform.create_or_update_masking_transformation(
                name="test-masking",
                template="builtin/creditcardnumber",
                masking_character="-",
                allowed_roles=["test-role"],
                mount_point=self.TEST_MOUNT_POINT,
            )
        )
        logging.debug(f"create_response: {create_response}")
        self.assertEqual(
            first=create_response.status_code,
            second=204,
        )

    @skipIf(
        utils.vault_version_lt("1.7.0"),
        "Expanded tokenization support added in Vault version v1.7.0",
    )
    def test_create_or_update_tokenization_transformation(self):
        create_response = (
            self.client.secrets.transform.create_or_update_tokenization_transformation(
                name="test-tokenization",
                max_ttl="60",
                mapping_mode="exportable",
                allowed_roles=["test-role"],
                mount_point=self.TEST_MOUNT_POINT,
            )
        )
        logging.debug(f"create_response: {create_response}")
        self.assertEqual(
            first=create_response.status_code,
            second=204,
        )

    def test_read_transformation(self):
        test_name = "test-transformation"
        template = "builtin/creditcardnumber"
        create_response = self.client.secrets.transform.create_or_update_transformation(
            name=test_name,
            transform_type="fpe",
            template=template,
            tweak_source="internal",
            allowed_roles=["test-role"],
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"create_response: {create_response}")
        read_response = self.client.secrets.transform.read_transformation(
            name=test_name,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"read_response: {read_response}")
        self.assertIn(
            member=template,
            container=read_response["data"]["templates"],
        )

    def test_list_transformations(self):
        test_name = "test-transformation"
        template = "builtin/creditcardnumber"
        create_response = self.client.secrets.transform.create_or_update_transformation(
            name=test_name,
            transform_type="fpe",
            template=template,
            tweak_source="internal",
            allowed_roles=["test-role"],
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"create_response: {create_response}")
        list_response = self.client.secrets.transform.list_transformations(
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"list_response: {list_response}")
        self.assertIn(
            member=test_name,
            container=list_response["data"]["keys"],
        )

    def test_delete_transformation(self):
        test_name = "test-transformation"
        template = "builtin/creditcardnumber"
        create_response = self.client.secrets.transform.create_or_update_transformation(
            name=test_name,
            transform_type="fpe",
            template=template,
            tweak_source="internal",
            allowed_roles=["test-role"],
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"create_response: {create_response}")
        delete_response = self.client.secrets.transform.delete_transformation(
            name=test_name,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"delete_response: {delete_response}")
        self.assertEqual(
            first=delete_response.status_code,
            second=204,
        )

    def test_create_or_update_template(self):
        test_name = "test-template"
        create_response = self.client.secrets.transform.create_or_update_template(
            name=test_name,
            template_type="regex",
            pattern="(\\d{9})",
            alphabet="builtin/numeric",
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"create_response: {create_response}")
        self.assertEqual(
            first=create_response.status_code,
            second=204,
        )

    def test_read_template(self):
        test_name = "test-template"
        test_pattern = "(\\d{9})"
        create_response = self.client.secrets.transform.create_or_update_template(
            name=test_name,
            template_type="regex",
            pattern=test_pattern,
            alphabet="builtin/numeric",
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"create_response: {create_response}")
        read_response = self.client.secrets.transform.read_template(
            name=test_name,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"read_response: {read_response}")
        self.assertIn(
            member=test_pattern,
            container=read_response["data"]["pattern"],
        )

    def test_list_templates(self):
        test_name = "test-template"
        test_pattern = "(\\d{9})"
        create_response = self.client.secrets.transform.create_or_update_template(
            name=test_name,
            template_type="regex",
            pattern=test_pattern,
            alphabet="builtin/numeric",
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"create_response: {create_response}")
        list_response = self.client.secrets.transform.list_templates(
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"list_response: {list_response}")
        self.assertIn(
            member=test_name,
            container=list_response["data"]["keys"],
        )

    def test_delete_template(self):
        test_name = "test-template"
        test_pattern = "(\\d{9})"
        create_response = self.client.secrets.transform.create_or_update_template(
            name=test_name,
            template_type="regex",
            pattern=test_pattern,
            alphabet="builtin/numeric",
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"create_response: {create_response}")
        delete_response = self.client.secrets.transform.delete_template(
            name=test_name,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"delete_response: {delete_response}")
        self.assertEqual(
            first=delete_response.status_code,
            second=204,
        )

    def test_create_or_update_alphabet(self):
        test_name = "test-alphabet"
        test_alphabet = "abc"
        create_response = self.client.secrets.transform.create_or_update_alphabet(
            name=test_name,
            alphabet=test_alphabet,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"create_response: {create_response}")
        self.assertEqual(
            first=create_response.status_code,
            second=204,
        )

    def test_read_alphabet(self):
        test_name = "test-alphabet"
        test_alphabet = "abc"
        create_response = self.client.secrets.transform.create_or_update_alphabet(
            name=test_name,
            alphabet=test_alphabet,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"create_response: {create_response}")
        read_response = self.client.secrets.transform.read_alphabet(
            name=test_name,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"read_response: {read_response}")
        self.assertEqual(
            first=test_alphabet,
            second=read_response["data"]["alphabet"],
        )

    def test_list_alphabets(self):
        test_name = "test-alphabet"
        test_alphabet = "abc"
        create_response = self.client.secrets.transform.create_or_update_alphabet(
            name=test_name,
            alphabet=test_alphabet,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"create_response: {create_response}")
        list_response = self.client.secrets.transform.list_alphabets(
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"list_response: {list_response}")
        self.assertIn(
            member=test_name,
            container=list_response["data"]["keys"],
        )

    def test_delete_alphabet(self):
        test_name = "test-alphabet"
        test_alphabet = "abc"
        create_response = self.client.secrets.transform.create_or_update_alphabet(
            name=test_name,
            alphabet=test_alphabet,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"create_response: {create_response}")
        delete_response = self.client.secrets.transform.delete_alphabet(
            name=test_name,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"delete_response: {delete_response}")
        self.assertEqual(
            first=delete_response.status_code,
            second=204,
        )

    def test_encode(self):
        role_name = "test-role"
        transformation_name = "test-transformation"
        transformations = [transformation_name]
        test_input_value = "1111-1111-1111-1111"
        expected_output = "****-****-****-****"
        create_role_response = self.client.secrets.transform.create_or_update_role(
            name=role_name,
            transformations=transformations,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"create_role_response: {create_role_response}")
        create_transform_response = (
            self.client.secrets.transform.create_or_update_transformation(
                name=transformation_name,
                transform_type="masking",
                template="builtin/creditcardnumber",
                tweak_source="internal",
                allowed_roles=[role_name],
                mount_point=self.TEST_MOUNT_POINT,
            )
        )
        logging.debug(f"create_transform_response: {create_transform_response}")
        encode_response = self.client.secrets.transform.encode(
            role_name=role_name,
            value=test_input_value,
            transformation=transformation_name,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"encode_response: {encode_response}")
        self.assertEqual(
            first=encode_response["data"]["encoded_value"],
            second=expected_output,
        )

    def test_decode(self):
        role_name = "test-role"
        transformation_name = "test-transformation"
        transformations = [transformation_name]
        test_input_value = "1111-1111-1111-1111"
        create_role_response = self.client.secrets.transform.create_or_update_role(
            name=role_name,
            transformations=transformations,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"create_role_response: {create_role_response}")
        create_transform_response = (
            self.client.secrets.transform.create_or_update_transformation(
                name=transformation_name,
                transform_type="fpe",
                template="builtin/creditcardnumber",
                tweak_source="internal",
                allowed_roles=[role_name],
                mount_point=self.TEST_MOUNT_POINT,
            )
        )
        logging.debug(f"create_transform_response: {create_transform_response}")
        encode_response = self.client.secrets.transform.encode(
            role_name=role_name,
            value=test_input_value,
            transformation=transformation_name,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"encode_response: {encode_response}")
        decode_response = self.client.secrets.transform.decode(
            role_name=role_name,
            value=encode_response["data"]["encoded_value"],
            transformation=transformation_name,
            mount_point=self.TEST_MOUNT_POINT,
        )
        logging.debug(f"decode_response: {decode_response}")
        self.assertEqual(
            first=decode_response["data"]["decoded_value"],
            second=test_input_value,
        )
