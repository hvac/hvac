TOTP
====

Create Key
-------------------

:py:meth:`hvac.api.secrets_engines.totp.create_key`

.. code:: python

	import hvac
	client = hvac.Client()

        create_key_response = client.secrets.totp.create_key(
           'mykey',
           url="otpauth://totp/Google:test@gmail.com?secret=Y64VEVMBTSXCYIWRSHRNDZW62MPGVU2G&issuer=Google"
        )
        print(f"New TOTP key response: {create_key_response}")


Read Key
-------------------------

:py:meth:`hvac.api.secrets_engines.totp.read_key`

.. code:: python

	import hvac
	client = hvac.Client()

        read_key_response = client.secrets.totp.read_key('mykey')
        print(f"Current TOTP key: {read_key_response['data']}")


List Keys
----------------

:py:meth:`hvac.api.secrets_engines.totp.list_keys`

.. code:: python

	import hvac
	client = hvac.Client()

        list_keys_response = client.secrets.totp.list_keys()
        print(f"Current keys : {list_keys_response['data']['keys']}")


Delete Key
---------------------

:py:meth:`hvac.api.secrets_engines.totp.delete_key`

.. code:: python

	import hvac
	client = hvac.Client()

        delete_key_response = client.secrets.totp.delete_key('mykey')
        print(f"Delete TOTP key response: {delete_key_response}")


Generate Code
---------------------


:py:meth:`hvac.api.secrets_engines.totp.generate_code`

.. code:: python

	import hvac
	client = hvac.Client()

        generate_code_response = client.secrets.totp.generate_code('mykey')
        print(f"Current OTP: {generate_code_response['data']['code']}")


Validate Code
---------------------

:py:meth:`hvac.api.secrets_engines.totp.validate_code`

.. code:: python

	import hvac
	client = hvac.Client()

        otp = client.secrets.totp.generate_code('mykey')['data']['code']
        validate_code_response = client.secrets.totp.validate_code('mykey', otp)
        print(f"Validate OTP: {validate_code_response['data']['valid']}")

