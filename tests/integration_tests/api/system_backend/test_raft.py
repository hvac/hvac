from unittest import TestCase, skipIf

from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestRaft(HvacIntegrationTestCase, TestCase):
    @skipIf(
        not utils.is_enterprise() or utils.vault_version_lt("1.8.0"),
        "Raft automated snapshots only supported in Enterprise Vault",
    )
    def test_create_raft_auto_config(self):
        raft_configs_dict = {
            "name": "my-local-auto-snapshot",
            "interval": "86400",
            "storage_type": "local",
            "retain": 5,
            "local_max_space": "100000",
            "path_prefix": "/opt/vault/backups",
            "file_prefix": "vault-raft-auto-snapshot",
        }

        self.client.sys.create_or_update_raft_auto_snapshot_config(
            name=raft_configs_dict["name"],
            interval=raft_configs_dict["interval"],
            storage_type=raft_configs_dict["storage_type"],
            retain=raft_configs_dict["retain"],
            local_max_space=raft_configs_dict["local_max_space"],
            path_prefix=raft_configs_dict["path_prefix"],
            file_prefix=raft_configs_dict["file_prefix"],
        )

        self.assertEqual(
            first=raft_configs_dict,
            second=self.client.sys.read_raft_auto_snapshot_config(
                raft_configs_dict["name"]
            )["data"],
        )

    @skipIf(
        not utils.is_enterprise() or utils.vault_version_lt("1.8.0"),
        "Raft automated snapshots only supported in Enterprise Vault",
    )
    def test_update_raft_auto_config(self):
        raft_configs_dict = {
            "name": "my-local-auto-snapshot",
            "interval": "86400",
            "storage_type": "local",
            "retain": 5,
            "local_max_space": "100000",
            "path_prefix": "/opt/vault/backups",
            "file_prefix": "vault-raft-auto-snapshot",
        }

        # Create initial configuration
        self.client.sys.create_or_update_raft_auto_snapshot_config(
            name=raft_configs_dict["name"],
            interval=raft_configs_dict["interval"],
            storage_type=raft_configs_dict["storage_type"],
            retain=raft_configs_dict["retain"],
            local_max_space=raft_configs_dict["local_max_space"],
            path_prefix=raft_configs_dict["path_prefix"],
            file_prefix=raft_configs_dict["file_prefix"],
        )

        raft_configs_dict["path_prefix"] = "/opt/vault/backups2"

        # Update configuration
        self.client.sys.create_or_update_raft_auto_snapshot_config(
            name=raft_configs_dict["name"],
            interval=raft_configs_dict["interval"],
            storage_type=raft_configs_dict["storage_type"],
            retain=raft_configs_dict["retain"],
            local_max_space=raft_configs_dict["local_max_space"],
            path_prefix=raft_configs_dict["path_prefix"],
            file_prefix=raft_configs_dict["file_prefix"],
        )

        self.assertEqual(
            first=raft_configs_dict,
            second=self.client.sys.read_raft_auto_snapshot_config(
                raft_configs_dict["name"]
            )["data"],
        )

    @skipIf(
        not utils.is_enterprise() or utils.vault_version_lt("1.8.0"),
        "Raft automated snapshots only supported in Enterprise Vault",
    )
    def test_read_raft_auto_config(self):
        raft_configs_dict = {
            "name": "my-local-auto-snapshot",
            "interval": "86400",
            "storage_type": "local",
            "retain": 5,
            "local_max_space": "100000",
            "path_prefix": "/opt/vault/backups",
            "file_prefix": "vault-raft-auto-snapshot",
        }

        # Create initial configuration
        self.client.sys.create_or_update_raft_auto_snapshot_config(
            name=raft_configs_dict["name"],
            interval=raft_configs_dict["interval"],
            storage_type=raft_configs_dict["storage_type"],
            retain=raft_configs_dict["retain"],
            local_max_space=raft_configs_dict["local_max_space"],
            path_prefix=raft_configs_dict["path_prefix"],
            file_prefix=raft_configs_dict["file_prefix"],
        )

        self.assertEqual(
            first=raft_configs_dict,
            second=self.client.sys.read_raft_auto_snapshot_config(
                raft_configs_dict["name"]
            )["data"],
        )

    @skipIf(
        not utils.is_enterprise() or utils.vault_version_lt("1.8.0"),
        "Raft automated snapshots only supported in Enterprise Vault",
    )
    def test_list_raft_auto_configs(self):
        raft_configs_dict = {
            "name": "my-local-auto-snapshot",
            "interval": "86400",
            "storage_type": "local",
            "retain": 5,
            "local_max_space": "100000",
            "path_prefix": "/opt/vault/backups",
            "file_prefix": "vault-raft-auto-snapshot",
        }

        # Create initial configuration
        self.client.sys.create_or_update_raft_auto_snapshot_config(
            name=raft_configs_dict["name"],
            interval=raft_configs_dict["interval"],
            storage_type=raft_configs_dict["storage_type"],
            retain=raft_configs_dict["retain"],
            local_max_space=raft_configs_dict["local_max_space"],
            path_prefix=raft_configs_dict["path_prefix"],
            file_prefix=raft_configs_dict["file_prefix"],
        )

        self.assertIn(
            member=raft_configs_dict["name"],
            container=self.client.sys.list_raft_auto_snapshot_configs()["data"]["keys"],
        )

    @skipIf(
        not utils.is_enterprise() or utils.vault_version_lt("1.8.0"),
        "Raft automated snapshots only supported in Enterprise Vault",
    )
    def test_delete_raft_auto_config(self):
        raft_configs_dict = {
            "name": "my-local-auto-snapshot",
            "interval": "86400",
            "storage_type": "local",
            "retain": 5,
            "local_max_space": "100000",
            "path_prefix": "/opt/vault/backups",
            "file_prefix": "vault-raft-auto-snapshot",
        }

        # Create initial configuration
        self.client.sys.create_or_update_raft_auto_snapshot_config(
            name=raft_configs_dict["name"],
            interval=raft_configs_dict["interval"],
            storage_type=raft_configs_dict["storage_type"],
            retain=raft_configs_dict["retain"],
            local_max_space=raft_configs_dict["local_max_space"],
            path_prefix=raft_configs_dict["path_prefix"],
            file_prefix=raft_configs_dict["file_prefix"],
        )

        # Path and file prefix can't be shared between configs
        raft_configs_dict["file_prefix"] = "vault-raft-auto-snapshot2"
        raft_configs_dict["path_prefix"] = "/opt/vault/backups2"

        # Create a second config because list endpoint raises a 404 if no configs exist
        self.client.sys.create_or_update_raft_auto_snapshot_config(
            name="my-local-auto-snapshot2",
            interval=raft_configs_dict["interval"],
            storage_type=raft_configs_dict["storage_type"],
            retain=raft_configs_dict["retain"],
            local_max_space=raft_configs_dict["local_max_space"],
            path_prefix=raft_configs_dict["path_prefix"],
            file_prefix=raft_configs_dict["file_prefix"],
        )

        self.client.sys.delete_raft_auto_snapshot_config(name=raft_configs_dict["name"])

        self.assertNotIn(
            member=raft_configs_dict,
            container=self.client.sys.list_raft_auto_snapshot_configs()["data"]["keys"],
        )

    @skipIf(
        not utils.is_enterprise() or utils.vault_version_lt("1.8.0"),
        "Raft automated snapshots only supported in Enterprise Vault",
    )
    def test_read_auto_snapshot_status(self):
        raft_configs_dict = {
            "name": "my-local-auto-snapshot",
            "interval": "86400",
            "storage_type": "local",
            "retain": 5,
            "local_max_space": "100000",
            "path_prefix": "/opt/vault/backups",
            "file_prefix": "vault-raft-auto-snapshot",
        }

        # Create initial configuration
        self.client.sys.create_or_update_raft_auto_snapshot_config(
            name=raft_configs_dict["name"],
            interval=raft_configs_dict["interval"],
            storage_type=raft_configs_dict["storage_type"],
            retain=raft_configs_dict["retain"],
            local_max_space=raft_configs_dict["local_max_space"],
            path_prefix=raft_configs_dict["path_prefix"],
            file_prefix=raft_configs_dict["file_prefix"],
        )

        # Confirm that key "data" exists within the response
        self.assertIn(
            member="data",
            container=self.client.sys.read_raft_auto_snapshot_status(
                raft_configs_dict["name"]
            ),
        )
