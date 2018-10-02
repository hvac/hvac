KV Secrets Engines
==================

The :py:class:`hvac.api.secrets_engines.Kv` instance under the :py:attr:`Client class's kv attribute<hvac.v1.Client.kv>` is a wrapper to expose either version 1 (:py:class:`KvV1<hvac.api.secrets_engines.KvV1>`) or version 2 of the key/value secrets engines' API methods (:py:class:`KvV2<hvac.api.secrets_engines.KvV2>`). At present, this class defaults to version 2 when accessing methods on the instance.



Setting the Default KV Version
------------------------------

:py:meth:`hvac.api.secrets_engines.KvV1.read_secret`

.. code:: python

    import hvac
    client = hvac.Client()

    client.kv.default_kv_version = 1
    client.kv.read_secret(path='hvac')  # => calls hvac.api.secrets_engines.KvV1.read_secret

Explicitly Calling a KV Version Method
--------------------------------------

:py:meth:`hvac.api.secrets_engines.KvV1.list_secrets`

.. code:: python

    import hvac
    client = hvac.Client()

    client.kv.v1.read_secret(path='hvac')
    client.kv.v2.read_secret_version(path='hvac')


Specific KV Version Usage
-------------------------

.. toctree::
   :maxdepth: 2

   ../secrets_engines/kv_v1
   ../secrets_engines/kv_v2
