from unittest import TestCase

from hvac.tests import utils


class TestPolicy(utils.HvacIntegrationTestCase, TestCase):

    def test_policy_manipulation(self):
        self.assertIn(
            member='root',
            container=self.client.sys.list_policies()['data']['policies'],
        )
        self.assertIsNone(self.client.sys.get_policy('test'))
        policy, parsed_policy = self.prep_policy('test')
        self.assertIn(
            member='test',
            container=self.client.sys.list_policies()['data']['policies'],
        )
        self.assertEqual(policy, self.client.sys.read_policy('test')['data']['rules'])
        self.assertEqual(parsed_policy, self.client.sys.get_policy('test', parse=True))

        self.client.sys.delete_policy(
            name='test',
        )
        self.assertNotIn(
            member='test',
            container=self.client.sys.list_policies()['data']['policies'],
        )

    def test_json_policy_manipulation(self):
        self.assertIn(
            member='root',
            container=self.client.sys.list_policies()['data']['policies'],
        )

        policy = '''
            path "sys" {
                policy = "deny"
            }
            path "secret" {
                policy = "write"
            }
        '''
        self.client.sys.create_or_update_policy(
            name='test',
            policy=policy,
        )
        self.assertIn(
            member='test',
            container=self.client.sys.list_policies()['data']['policies'],
        )

        self.client.delete_policy('test')
        self.assertNotIn(
            member='test',
            container=self.client.sys.list_policies()['data']['policies'],
        )
