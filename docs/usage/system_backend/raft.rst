Raft
====

:py:meth:`hvac.api.system_backend.Raft`

.. contents::
   :local:
   :depth: 1

Join Raft Cluster
-----------------

:py:meth:`hvac.api.system_backend.Raft.join_raft_cluster`

.. code:: python

    import hvac
    client = hvac.Client()

    client.sys.join_raft_cluster(
        leader_api_addr='https://some-vault-node',
    )

Read Raft Configuration
-----------------------

:py:meth:`hvac.api.system_backend.Raft.read_raft_config`

.. code:: python

    import hvac
    client = hvac.Client()

    raft_config = c.sys.read_raft_config()
    num_servers_in_cluster = len(raft_config['data']['config']['servers'])

Remove Raft Node
----------------

:py:meth:`hvac.api.system_backend.Raft.remove_raft_node`

.. code:: python

    import hvac
    client = hvac.Client()

    client.sys.remove_raft_node(
        server_id='i-somenodeid',
    )

Read Raft Auto-Snapshot Status
------------------------------

:py:meth:`hvac.api.system_backend.Raft.read_raft_auto_snapshot_status`

.. code:: python

    import hvac
    client = hvac.Client()

    client.sys.read_raft_auto_snapshot_status("my-local-auto-snapshot")

Read Raft Auto-Snapshot Configuration
-------------------------------------

:py:meth:`hvac.api.system_backend.Raft.read_raft_auto_snapshot_config`

.. code:: python

    import hvac
    client = hvac.Client()

    client.sys.read_raft_auto_snapshot_config("my-local-auto-snapshot")

List Raft Auto-Snapshot Configurations
--------------------------------------

:py:meth:`hvac.api.system_backend.Raft.list_raft_auto_snapshot_configs`

.. code:: python

    import hvac
    client = hvac.Client()

    client.sys.list_raft_auto_snapshot_configs()

Create or Update Raft Auto-Snapshot Configuration
-------------------------------------------------

:py:meth:`hvac.api.system_backend.Raft.create_or_update_raft_auto_snapshot_config`

.. code:: python

    import hvac
    client = hvac.Client()

    client.sys.create_or_update_raft_auto_snapshot_config(
        name="my-local-auto-snapshot",
        interval="1d",
        storage_type="local",
        retain=5,
        local_max_space="100000",
        path_prefix="/opt/vault/backups",
        file_prefix="vault-raft-auto-snapshot"
    )

Delete Raft Auto-Snapshot Configuration
---------------------------------------

:py:meth:`hvac.api.system_backend.Raft.delete_raft_auto_snapshot_config`

.. code:: python

    import hvac
    client = hvac.Client()

    client.sys.delete_raft_auto_snapshot_config(
        name="my-local-auto-snapshot",
    )
