Policies
========

.. contents::
   :local:
   :depth: 1

.. testsetup:: sys_policies

    client.sys.enable_secrets_engine(
    backend_type="kv",
    path="test",
    )

Read ACL Policy
---------------

.. automethod:: hvac.api.system_backend.PasswordPolicy.read_acl_policy
   :noindex:

Examples
````````

.. testcode:: sys_policies

    import hvac
    client = hvac.Client(url="https://127.0.0.1:8200")

    # Create PasswordPolicy Policy
    client.sys.create_or_update_pp_policy(
            name="test-passwd-policy", policy='length=14\nrule \"charset\" {\"charset\" = \"abcdefght\"\nmin-char=4\n}',
        )

    client.sys.read_pp_policy("test-passwd-policy")

Create or Update Password Policy
---------------------------

.. automethod:: hvac.api.system_backend.PasswordPolicy.create_or_update_pp_policy
   :noindex:

.. testcode:: sys_policies

    import hvac
    client = hvac.Client(url="https://127.0.0.1:8200")

    # Create Password Policy
    client.sys.create_or_update_pp_policy(
            name="test-password-policy", policy='length=14\nrule \"charset\" {\"charset\" = \"abcdefght\"\nmin-char=4\n}',
        )

    # Update Password Policy Policy
    client.sys.create_or_update_pp_policy(
            name="test-password-policy", policy='length=14\nrule \"charset\" {\"charset\" = \"abcdefght\"\nmin-char=4\n}',
        )

List Password Policies
-----------------

.. automethod:: hvac.api.system_backend.PasswordPolicy.list_pp_policies
   :noindex:

Examples
````````

.. testcode:: sys_policies

    import hvac
    client = hvac.Client(url="https://127.0.0.1:8200")
    
    client.sys.create_or_update_pp_policy(
            name="test-password-policy", policy='length=14\nrule \"charset\" {\"charset\" = \"abcdefght\"\nmin-char=4\n}',
        )
    client.sys.list_pp_policies()

Delete Password Policy
-----------------

.. automethod:: hvac.api.system_backend.PasswordPolicy.delete_pp_policy
   :noindex:

Examples
````````

.. testcode:: sys_policies

    import hvac
    client = hvac.Client(url="https://127.0.0.1:8200")
    client.sys.delete_pp_policy("test-password-policy")
