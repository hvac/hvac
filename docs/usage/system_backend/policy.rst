Policy
======


List Policies
-------------

:py:meth:`hvac.api.system_backend.policy.list_policies`

.. code:: python

	import hvac
	client = hvac.Client()

	list_policies_resp = client.sys.list_policies()['data']['policies']
	print('List of currently configured policies: %s' % list_policies_resp)


Read Policy
-----------

:py:meth:`hvac.api.system_backend.policy.read_policy`

.. code:: python

	import hvac
	client = hvac.Client()

	hvac_policy_rules = client.sys.read_policy(name='hvac-policy')['data']['rules']
	print('Rules for the hvac policy are: %s' % hvac_policy_rules)


Get Policy
----------

:py:meth:`hvac.api.system_backend.policy.create_or_update_policy`

.. code:: python

	import hvac
	client = hvac.Client()

	hvac_policy_rules = client.sys.get_policy(name='hvac-policy', parse=True)
	print('Rules for the hvac policy are: %s' % hvac_policy_rules)



Create Or Update Policy
-----------------------

:py:meth:`hvac.api.system_backend.policy.read_status`

.. code:: python

	import hvac
	client = hvac.Client()

	policy = '''
		path "sys" {
			policy = "deny"
		}
		path "secret" {
			policy = "write"
		}
	'''
	client.sys.create_or_update_policy(
		name='secret-writer',
		policy=policy,
	)


Delete Policy
-------------

:py:meth:`hvac.api.system_backend.policy.delete_policy`

.. code:: python

	import hvac
	client = hvac.Client()

	client.sys.delete_policy(
		name='secret-writer',
	)


