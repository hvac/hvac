KV Secrets Engines
==================

The :py:class:`hvac.api.secrets_engines.Kv` instance under the :py:attr:`Client class's secrets.kv attribute<hvac.v1.Client.secrets.kv>` is a wrapper to expose either version 1 (:py:class:`KvV1<hvac.api.secrets_engines.KvV1>`) or version 2 of the key/value secrets engines' API methods (:py:class:`KvV2<hvac.api.secrets_engines.KvV2>`). At present, this class defaults to version 2 when accessing methods on the instance.



Setting the Default KV Version
------------------------------

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.kv.default_kv_version = 1
    client.secrets.kv.read_secret(path='hvac')  # => calls hvac.api.secrets_engines.KvV1.read_secret

Explicitly Calling a KV Version Method
--------------------------------------

.. code:: python

    import hvac
    client = hvac.Client()

    client.secrets.kv.v1.read_secret(path='hvac')
    client.secrets.kv.v2.read_secret_version(path='hvac')


Specific KV Version Usage
-------------------------

.. toctree::
   :maxdepth: 2

   ../secrets_engines/kv_v1
   ../secrets_engines/kv_v2
