from unittest import TestCase

from hvac import exceptions
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase

TEST_AUTH_PATH = "userpass"


class TestUserpass(HvacIntegrationTestCase, TestCase):
    @classmethod
    def setUpClass(cls):
        super(TestUserpass, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestUserpass, cls).tearDownClass()

    def setUp(self):
        super(TestUserpass, self).setUp()
        if "%s/" % TEST_AUTH_PATH not in self.client.sys.list_auth_methods():
            self.client.sys.enable_auth_method(
                method_type="userpass", path=TEST_AUTH_PATH
            )

    def tearDown(self):
        super(TestUserpass, self).tearDown()
        self.client.sys.disable_auth_method(
            path=TEST_AUTH_PATH,
        )

    def test_userpass_auth(self):
        self.client.write(
            "auth/userpass/users/testuser", password="testpass", policies="not_root"
        )

        result = self.client.auth.userpass.login("testuser", "testpass")

        assert self.client.token == result["auth"]["client_token"]
        assert self.client.is_authenticated()

        self.client.token = self.manager.root_token

    def test_create_userpass(self):
        self.client.auth.userpass.create_or_update_user(
            "testcreateuser", "testcreateuserpass", policies="not_root"
        )

        result = self.client.auth.userpass.login("testcreateuser", "testcreateuserpass")

        assert self.client.token == result["auth"]["client_token"]
        assert self.client.is_authenticated()

        # Test ttl:
        self.client.token = self.manager.root_token
        self.client.auth.userpass.create_or_update_user(
            "testcreateuser", "testcreateuserpass", policies="not_root", ttl="10s"
        )
        self.client.token = result["auth"]["client_token"]

        result = self.client.auth.userpass.login("testcreateuser", "testcreateuserpass")

        assert result["auth"]["lease_duration"] == 10

        self.client.token = self.manager.root_token

    def test_list_userpass(self):
        # add some users and confirm that they show up in the list
        self.client.auth.userpass.create_or_update_user(
            "testuserone", "testuseronepass", policies="not_root"
        )
        self.client.auth.userpass.create_or_update_user(
            "testusertwo", "testusertwopass", policies="not_root"
        )

        user_list = self.client.auth.userpass.list_user()
        assert "testuserone" in user_list["data"]["keys"]
        assert "testusertwo" in user_list["data"]["keys"]

        # delete all the users and confirm that list_userpass() doesn't fail
        for user in user_list["data"]["keys"]:
            self.client.auth.userpass.delete_user(user)

        with self.assertRaises(exceptions.InvalidPath):
            self.client.auth.userpass.list_user()

    def test_read_userpass(self):
        # create user to read
        self.client.auth.userpass.create_or_update_user(
            "readme", "mypassword", policies="not_root"
        )

        # test that user can be read
        read_user = self.client.auth.userpass.read_user("readme")
        assert "not_root" in read_user["data"]["policies"]

        # teardown
        self.client.sys.disable_auth_method("userpass")

    def test_update_userpass_policies(self):
        if "userpass/" not in self.client.sys.list_auth_methods()["data"]:
            self.client.sys.enable_auth_method("userpass")

        # create user and then update its policies
        self.client.auth.userpass.create_or_update_user(
            "updatemypolicies", "mypassword", policies="not_root"
        )
        self.client.auth.userpass.create_or_update_user(
            "updatemypolicies", policies="somethingelse"
        )

        # test that policies have changed
        updated_user = self.client.auth.userpass.read_user("updatemypolicies")
        assert "somethingelse" in updated_user["data"]["policies"]

    def test_update_userpass_password(self):
        # create user and then change its password
        self.client.auth.userpass.create_or_update_user(
            "changeme", "mypassword", policies="not_root"
        )
        self.client.auth.userpass.update_password_on_user("changeme", "mynewpassword")

        # test that new password authenticates user
        result = self.client.auth.userpass.login("changeme", "mynewpassword")
        assert self.client.token == result["auth"]["client_token"]
        assert self.client.is_authenticated()

        # teardown
        self.client.token = self.manager.root_token

    def test_delete_userpass(self):
        self.client.auth.userpass.create_or_update_user(
            "testcreateuser", "testcreateuserpass", policies="not_root"
        )

        result = self.client.auth.userpass.login("testcreateuser", "testcreateuserpass")

        assert self.client.token == result["auth"]["client_token"]
        assert self.client.is_authenticated()

        self.client.token = self.manager.root_token
        self.client.auth.userpass.delete_user("testcreateuser")
        self.assertRaises(
            exceptions.InvalidRequest,
            self.client.auth.userpass.login,
            "testcreateuser",
            "testcreateuserpass",
        )
