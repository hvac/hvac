Policy
======

Manipulate policies
-------------------

.. code:: python

	policies = client.sys.list_policies()['data']['policies'] # => ['root']

	policy = """
	path "sys" {
	  policy = "deny"
	}

	path "secret" {
	  policy = "write"
	}

	path "secret/foo" {
	  policy = "read"
	}
	"""

	client.sys.create_or_update_policy(
		name='secret-writer',
		policy=policy,
	)

	client.sys.delete_policy('oldthing')

	policy = client.sys.get_policy('mypolicy')

	# Requires pyhcl to automatically parse HCL into a Python dictionary
	policy = client.sys.get_policy('mypolicy', parse=True)

Using Python Variable(s) In Policy Rules
````````````````````````````````````````

.. code:: python

	import hvac

	client = hvac.Client()

	key = 'some-key-string'

	policy_body = """
	path "transit/encrypt/%s" {
		capabilities = "update"
	}
	""" % key
	client.sys.create_or_update_policy(name='my-policy-name', rules=policy_body)


List Policies
-------------

:py:meth:`hvac.api.system_backend.Policy.list_policies`

.. code:: python

	import hvac
	client = hvac.Client()

	list_policies_resp = client.sys.list_policies()['data']['policies']
	print('List of currently configured policies: %s' % list_policies_resp)


Read Policy
-----------

:py:meth:`hvac.api.system_backend.Policy.read_policy`

.. code:: python

	import hvac
	client = hvac.Client()

	hvac_policy_rules = client.sys.read_policy(name='hvac-policy')['data']['rules']
	print('Rules for the hvac policy are: %s' % hvac_policy_rules)


Get Policy
----------

:py:meth:`hvac.api.system_backend.Policy.get_policy`

.. code:: python

	import hvac
	client = hvac.Client()

	hvac_policy_rules = client.sys.get_policy(name='hvac-policy', parse=True)
	print('Rules for the hvac policy are: %s' % hvac_policy_rules)



Create Or Update Policy
-----------------------

:py:meth:`hvac.api.system_backend.Policy.create_or_update_policy`

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

:py:meth:`hvac.api.system_backend.Policy.delete_policy`

.. code:: python

	import hvac
	client = hvac.Client()

	client.sys.delete_policy(
		name='secret-writer',
	)


