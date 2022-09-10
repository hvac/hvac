import logging
from unittest import TestCase
from hvac.api.system_backend import mount

from parameterized import parameterized, param

from hvac.exceptions import InvalidPath, InvalidRequest, ParamValidationError

from hvac.constants.totp import ALLOWED_DIGITS

from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase

class TestTotp(HvacIntegrationTestCase, TestCase):
    TEST_MOUNT_POINT = "totp-integration-test"
    expected_status_code = 204

    def setUp(self):
        super().setUp()
        self.client.sys.enable_secrets_engine(
            backend_type="totp",
            path=self.TEST_MOUNT_POINT,
        )

    def tearDown(self):
        self.client.sys.disable_secrets_engine(path=self.TEST_MOUNT_POINT)
        super().tearDown()
    
    @parameterized.expand(
        [
            param(
                "with_url", 
                url="otpauth://totp/Google:test@gmail.com?secret=Y64VEVMBTSXCYIWRSHRNDZW62MPGVU2G&issuer=Google"
            ),
            param(
                "generate",
                generate=True,
                issuer="Google",
                account_name="test@gmail.com"
            ),
            param(
                "no_issuer",
                generate=True,
                raises=ParamValidationError,
                exception_message="required issuer and account_name when generate is true" 
            ),
            param(
                "invalid_skew",
                generate=True,
                issuer="Google",
                account_name="test@gmail.com",
                skew=2,
                raises=ParamValidationError,
                exception_message="value can be either 0 or 1" 
            ),
            param(
                "no_key",
                raises=ParamValidationError,
                exception_message="key is required if generate is false and url is empty" 
            ),
            param(
                "invalid_algo",
                generate=True,
                issuer="Google",
                account_name="test@gmail.com",
                algorithm="SHA-1",
                raises=ParamValidationError,
                exception_message='Options include "SHA1", "SHA256" and "SHA512"' 
            ),
            param(
                "invalid_digits",
                generate=True,
                issuer="Google",
                account_name="test@gmail.com",
                digits="10",
                raises=ParamValidationError,
                exception_message="This value can be either 0 or 1. Only used if generate is true" 
            ),
            param(
                "qr_size_0",
                generate=True,
                issuer="Google",
                account_name="test@gmail.com",
                qr_size=0
            ),
        ]
    )
    def test_create_key(
        self, 
        name,
        generate=False,
        exported=True,
        key_size=20,
        url="",
        key="",
        issuer="",
        account_name="",
        period=30,
        algorithm="SHA1",
        digits=6,
        skew=1,
        qr_size=200,
        mount_point=TEST_MOUNT_POINT,
        raises=None,
        exception_message="",
    ):
        if raises:
            with self.assertRaises(raises) as cm:
                create_key_response = self.client.secrets.totp.create_key(
                    name=name,
                    generate=generate,
                    exported=exported,
                    key_size=key_size,
                    url=url,
                    key=key,
                    issuer=issuer,
                    account_name=account_name,
                    period=period,
                    algorithm=algorithm,
                    digits=digits,
                    skew=skew,
                    qr_size=qr_size,
                    mount_point=mount_point,
                )
            logging.debug(str(cm.exception))
            self.assertIn(
                member=exception_message,
                container=str(cm.exception),
            )
        else:
            create_key_response = self.client.secrets.totp.create_key(
                name=name,
                generate=generate,
                exported=exported,
                key_size=key_size,
                url=url,
                key=key,
                issuer=issuer,
                account_name=account_name,
                period=period,
                algorithm=algorithm,
                digits=digits,
                skew=skew,
                qr_size=qr_size,
                mount_point=mount_point,
            )
            logging.debug("create_key_response: %s" % create_key_response)

            if generate:
                self.assertEqual(
                    first=sorted(list(create_key_response.keys())),
                    second=['auth', 'data', 'lease_duration', 'lease_id', 'renewable', 'request_id', 'warnings', 'wrap_info'],
                )
            else:
                self.assertEqual(
                    first=create_key_response.status_code,
                    second=self.expected_status_code,
                )

    @parameterized.expand(
        [
            param("read_key"),
            param("invalid_path",False, raises=InvalidPath)
        ]
    )
    def test_read_key(
        self,
        name,
        create=True,
        mount_point=TEST_MOUNT_POINT,
        raises=None,
        exception_message="",
    ):
        if create:
            create_key_response = self.client.secrets.totp.create_key(
                    name=name,
                    url="otpauth://totp/%s?secret=dGVzdAo=" % name,
                    mount_point=mount_point,
                )
            logging.debug("create_key_response: %s" % create_key_response)
            
            read_key_response = self.client.secrets.totp.read_key(
                        name=name,
                        mount_point=mount_point
            )
            logging.debug("read_key_response: %s" % read_key_response)
            self.assertEqual(
                first=sorted(list(read_key_response.keys())),
                second=['auth', 'data', 'lease_duration', 'lease_id', 'renewable', 'request_id', 'warnings', 'wrap_info']
            )
        else: 
            with self.assertRaises(raises) as cm:
                read_key_response = self.client.secrets.totp.read_key(
                            name=name,
                            mount_point=mount_point
                )
                logging.debug(str(cm.exception))


    @parameterized.expand(
        [
            param(create=True),
            param(create=False, raises=InvalidPath),
        ]
    )
    def test_list_keys(
        self,
        create=False,
        mount_point=TEST_MOUNT_POINT,
        raises=None,
        exception_message="",
    ):
        if create:
            for i in range(3):
                create_key_response = self.client.secrets.totp.create_key(
                        name="list_key_%d" % i,
                        url="otpauth://totp/%d?secret=dGVzdAo=" % i,
                        mount_point=mount_point,
                    )
                logging.debug("create_key_response: %s" % create_key_response)
            
            list_keys_response = self.client.secrets.totp.list_keys(
                        mount_point=mount_point
            )
            logging.debug("read_key_response: %s" % list_keys_response)
            self.assertEqual(
                first=len(list_keys_response['data']['keys']),
                second=3
            )
        else: 
            with self.assertRaises(raises) as cm:
                list_keys_response = self.client.secrets.totp.list_keys(
                            mount_point=mount_point
                )
                logging.debug(str(cm.exception))
        
    @parameterized.expand(
        [
            param("test", create=True),
            param("delete_nonexists", create=False, raises=InvalidPath),
        ]
    )
    def test_delete_key(
        self,
        name,
        create=False,
        mount_point=TEST_MOUNT_POINT,
        raises=None,
        exception_message="",
    ):
        if create:
            create_key_response = self.client.secrets.totp.create_key(
                    name=name,
                    url="otpauth://totp/%s?secret=dGVzdAo=" % name,
                    mount_point=mount_point,
                )
            logging.debug("create_key_response: %s" % create_key_response)
            
            delete_key_response = self.client.secrets.totp.delete_key(
                    name=name,
                    mount_point=mount_point
            )
            logging.debug("delete_key_response: %s" % delete_key_response)
            self.assertEqual(
                    first=delete_key_response.status_code,
                    second=self.expected_status_code,
            )
        else: 
            # with self.assertRaises(raises) as cm:
            delete_key_response = self.client.secrets.totp.delete_key(
                name=name,
                mount_point=mount_point
            )
            logging.debug("delete_key_response: %s" % delete_key_response)
            self.assertEqual(
                    first=delete_key_response.status_code,
                    second=self.expected_status_code,
            )

    @parameterized.expand(
    [
        param("generate_code"),
        param("code_nonexists", False, raises=InvalidRequest)
    ]
    )
    def test_generate_code(
        self,
        name,
        create=True,
        mount_point=TEST_MOUNT_POINT,
        raises=None,
        exception_message="",
    ):
        if create:
            create_key_response = self.client.secrets.totp.create_key(
                    name=name,
                    url="otpauth://totp/%s?secret=dGVzdAo=" % name,
                    mount_point=mount_point,
                )
            logging.debug("create_key_response: %s" % create_key_response)
            
            generate_code_response = self.client.secrets.totp.generate_code(
                        name=name,
                        mount_point=mount_point
            )
            logging.debug("generate_code_response: %s" % generate_code_response)
            self.assertTrue(generate_code_response['data']['code'].isdigit())
            self.assertTrue(len(generate_code_response['data']['code']) in ALLOWED_DIGITS)
        else: 
            with self.assertRaises(raises) as cm:
                generate_code_response = self.client.secrets.totp.generate_code(
                            name=name,
                            mount_point=mount_point
                )
                logging.debug(str(cm.exception))

    @parameterized.expand(
    [
        param("test"),
        param("invalid_code", "000000"),
        param("validate_nonexists", False, raises=InvalidRequest)
    ]
    )
    def test_validate_code(
        self,
        name,
        code="",
        create=True,
        mount_point=TEST_MOUNT_POINT,
        raises=None,
        exception_message="",
    ):
        if create:
            create_key_response = self.client.secrets.totp.create_key(
                    name=name,
                    url="otpauth://totp/%s?secret=dGVzdAo=" % name,
                    mount_point=mount_point,
                )
            logging.debug("create_key_response: %s" % create_key_response)
            generate_code_response = self.client.secrets.totp.generate_code(
                        name=name,
                        mount_point=mount_point
            )
            logging.debug("generate_code_response: %s" % generate_code_response)
                
            if code == "":
                token = generate_code_response['data']['code']
            else: 
                token = list(filter(lambda i: i != code, [ str(i).zfill(6) for i in range(0,10**6) ]))[0]
            logging.debug("validating with code: %s" % token)
            validate_code_response = self.client.secrets.totp.validate_code(
                        name=name,
                        code=token,
                        mount_point=mount_point
            )
            logging.debug("validate_code_response: %s" % validate_code_response)
            if code == "":
                self.assertTrue(validate_code_response['data']['valid'])
            else:
                self.assertFalse(validate_code_response['data']['valid'])
        else: 
            with self.assertRaises(raises) as cm:
                validate_code_response = self.client.secrets.totp.validate_code(
                            name=name,
                            code=code,
                            mount_point=mount_point
                )
                logging.debug(str(cm.exception))
