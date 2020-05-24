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
