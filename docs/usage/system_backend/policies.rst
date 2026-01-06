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

.. automethod:: hvac.api.system_backend.Policies.read_acl_policy
   :noindex:

Examples
````````

.. testcode:: sys_policies

    import hvac
    client = hvac.Client(url="https://127.0.0.1:8200")

    # Create ACL Policy
    client.sys.create_or_update_acl_policy(
            name="test-acl-policy", policy='path "sys/health" { capabilities = ["read", "sudo"]}',
        )

    client.sys.read_acl_policy("test-acl-policy")

Create or Update ACL Policy
---------------------------

.. automethod:: hvac.api.system_backend.Policies.create_or_update_acl_policy
   :noindex:

.. testcode:: sys_policies

    import hvac
    client = hvac.Client(url="https://127.0.0.1:8200")

    # Create ACL Policy
    client.sys.create_or_update_acl_policy(
            name="test-acl-policy", policy='path "sys/health" { capabilities = ["read", "sudo"]}',
        )

    # Update ACL Policy
    client.sys.create_or_update_acl_policy(
            name="test-acl-policy", policy='path "sys/health" { capabilities = ["read"]}',
        )

List ACL Policies
-----------------

.. automethod:: hvac.api.system_backend.Policies.list_acl_policies
   :noindex:

Examples
````````

.. testcode:: sys_policies

    import hvac
    client = hvac.Client(url="https://127.0.0.1:8200")
    
    client.sys.create_or_update_acl_policy(
            name="test-acl-policy", policy='path "sys/health" { capabilities = ["read"]}',
        )
    client.sys.list_acl_policies()

Delete ACL Policy
-----------------

.. automethod:: hvac.api.system_backend.Policies.delete_acl_policy
   :noindex:

Examples
````````

.. testcode:: sys_policies

    import hvac
    client = hvac.Client(url="https://127.0.0.1:8200")
    client.sys.delete_acl_policy("test-acl-policy")

Read RGP Policy
---------------

.. automethod:: hvac.api.system_backend.Policies.read_rgp_policy
   :noindex:

Examples
````````

.. testcode:: sys_policies
    :skipif: not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url="https://127.0.0.1:8200")

    policy = """import "time"
    import "strings"

    main = rule when not strings.has_prefix(request.path, "auth/ldap/login") {
        time.load(token.creation_time).unix > time.load("2017-09-17T13:25:29Z").unix
    }
    """

    client.sys.create_or_update_rgp_policy(
        name="test-rgp-policy", policy=policy, enforcement_level="soft-mandatory"
    )

    client.sys.read_rgp_policy("test-rgp-policy")

Create or Update RGP Policy
---------------------------

.. automethod:: hvac.api.system_backend.Policies.create_or_update_rgp_policy
   :noindex:

.. testcode:: sys_policies
    :skipif: not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url="https://127.0.0.1:8200")

    policy = """import "time"
    import "strings"

    main = rule when not strings.has_prefix(request.path, "auth/ldap/login") {
        time.load(token.creation_time).unix > time.load("2017-09-17T13:25:29Z").unix
    }
    """

    # Create RGP Policy
    client.sys.create_or_update_rgp_policy(
            name="test-rgp-policy", policy=policy, enforcement_level="soft-mandatory"
        )

    # Update RGP Policy
    client.sys.create_or_update_rgp_policy(
            name="test-rgp-policy", policy=policy, enforcement_level="hard-mandatory",
        )

List RGP Policies
-----------------

.. automethod:: hvac.api.system_backend.Policies.list_rgp_policies
   :noindex:

Examples
````````

.. testcode:: sys_policies
    :skipif: not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url="https://127.0.0.1:8200")
    
    policy = """import "time"
    import "strings"

    main = rule when not strings.has_prefix(request.path, "auth/ldap/login") {
        time.load(token.creation_time).unix > time.load("2017-09-17T13:25:29Z").unix
    }
    """

    client.sys.create_or_update_rgp_policy(
            name="test-rgp-policy", policy=policy, enforcement_level="soft-mandatory"
        )
    client.sys.list_rgp_policies()

Delete RGP Policy
-----------------

.. automethod:: hvac.api.system_backend.Policies.delete_rgp_policy
   :noindex:

Examples
````````

.. testcode:: sys_policies
    :skipif: not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url="https://127.0.0.1:8200")
    client.sys.delete_rgp_policy("test-rgp-policy")

Read EGP Policy
---------------

.. automethod:: hvac.api.system_backend.Policies.read_egp_policy
   :noindex:

Examples
````````

.. testcode:: sys_policies
    :skipif: not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url="https://127.0.0.1:8200")

    policy = """import "time"
    import "strings"

    main = rule when not strings.has_prefix(request.path, "auth/ldap/login") {
        time.load(token.creation_time).unix > time.load("2017-09-17T13:25:29Z").unix
    }
    """

    # Create EGP Policy
    client.sys.create_or_update_egp_policy(
            name="test-egp-policy", policy=policy, enforcement_level="soft-mandatory", paths=["/test"]
        )

    client.sys.read_egp_policy("test-egp-policy")

Create or Update EGP Policy
---------------------------

.. automethod:: hvac.api.system_backend.Policies.create_or_update_egp_policy
   :noindex:

.. testcode:: sys_policies
    :skipif: not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url="https://127.0.0.1:8200")

    policy = """import "time"
    import "strings"

    main = rule when not strings.has_prefix(request.path, "auth/ldap/login") {
        time.load(token.creation_time).unix > time.load("2017-09-17T13:25:29Z").unix
    }
    """

    # Create EGP Policy
    client.sys.create_or_update_egp_policy(
            name="test-egp-policy", policy=policy, enforcement_level="soft-mandatory", paths=["/test"]
        )

    # Update EGP Policy
    client.sys.create_or_update_egp_policy(
            name="test-egp-policy", policy=policy, enforcement_level="hard-mandatory", paths=["/test"],
        )

List EGP Policies
-----------------

.. automethod:: hvac.api.system_backend.Policies.list_egp_policies
   :noindex:

Examples
````````

.. testcode:: sys_policies
    :skipif: not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url="https://127.0.0.1:8200")
    
    policy = """import "time"
    import "strings"

    main = rule when not strings.has_prefix(request.path, "auth/ldap/login") {
        time.load(token.creation_time).unix > time.load("2017-09-17T13:25:29Z").unix
    }
    """

    client.sys.create_or_update_egp_policy(
            name="test-egp-policy1", policy=policy, enforcement_level="soft-mandatory", paths=["/test"]
        )
    client.sys.list_egp_policies()

Delete EGP Policy
-----------------

.. automethod:: hvac.api.system_backend.Policies.delete_egp_policy
   :noindex:

Examples
````````

.. testcode:: sys_policies
    :skipif: not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url="https://127.0.0.1:8200")
    client.sys.delete_egp_policy("test-egp-policy")

List Password Policies
----------------------

.. automethod:: hvac.api.system_backend.Policies.list_password_policies
   :noindex:

Examples
````````

.. testcode:: sys_policies
    :skipif: test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url="https://127.0.0.1:8200")
    client.sys.list_password_policies()

Read Password Policy
--------------------

.. automethod:: hvac.api.system_backend.Policies.read_password_policy
   :noindex:

Examples
````````

.. testcode:: sys_policies
    :skipif: test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url="https://127.0.0.1:8200")
    client.sys.read_password_policy("password_policy_name")

Create or Update Password Policy
--------------------------------

.. automethod:: hvac.api.system_backend.Policies.create_or_update_password_policy
   :noindex:

Examples
````````

.. testcode:: sys_policies
    :skipif: test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url="https://127.0.0.1:8200")

    # create policy
    policy_name = "test-password-policy"
    policy = 'length = 20 rule "charset" { charset = "abcde" }'

    self.client.sys.create_or_update_password_policy(
        name=policy_name, policy=policy
    )


Delete Password Policy
----------------------

.. automethod:: hvac.api.system_backend.Policies.delete_password_policy
   :noindex:

Examples
````````

.. testcode:: sys_policies
    :skipif: test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url="https://127.0.0.1:8200")
    client.sys.delete_password_policy("password_policy_name")

Generate Password
-----------------

.. automethod:: hvac.api.system_backend.Policies.generate_password
   :noindex:

Examples
````````

.. testcode:: sys_policies
    :skipif: test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url="https://127.0.0.1:8200")
    generated_password = client.sys.generate_password('password_policy_name')['data']['password']
