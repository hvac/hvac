Kubernetes
==========
.. note::
    Default mount point is 'kubernetes' and can be changed in every function. Example 'mount_point=k8s' 


Authentication
--------------

Source reference: :py:meth:`hvac.api.auth_methods.Kubernetes.login`

.. code:: python

    from hvac import Client
    from hvac.api.auth_methods import Kubernetes

    client = Client(url=url, verify=certificate_path)

    # Kubernetes (from k8s pod)
    f = open('/var/run/secrets/kubernetes.io/serviceaccount/token')
    jwt = f.read()
    Kubernetes(client.adapter).login(role=role, jwt=jwt)


Configure
---------

Source reference: :py:meth:`hvac.api.auth_methods.Kubernetes.configure`

.. code:: python

    import hvac
    from hvac.api.auth_methods import Kubernetes

    client = Client(url=url, verify=certificate_path)

    Kubernetes(client.adapter).configure(
        token_reviewer_jwt=token_reviewer_jwt,
        kubernetes_host="https://api.kubernetes.tld:6443",
        kubernetes_ca_cert=ca.pem,
    )


Read Config
-----------

Source reference: :py:meth:`hvac.api.auth_methods.Kubernetes.read_config`

.. code:: python

    import hvac
    from hvac.api.auth_methods import Kubernetes

    client = Client(url=url, verify=certificate_path)

    read_config = Kubernetes(client.adapter).read_config()
    print(f'The configured kubernetes host is: {read_config['kubernetes_host']}')


Create Role
-----------

Source reference: :py:meth:`hvac.api.auth_methods.Kubernetes.create_role`

.. code:: python


    import hvac
    from hvac.api.auth_methods import Kubernetes

    client = Client(url=url, verify=certificate_path)

    Kubernetes(client.adapter).create_role(
		name='some-kubernetes-role-name',
        bound_service_account_names="*".
        bound_service_account_namespaces="*",
        bound_service_account_namespace_selector="{\"matchLabels\":{\"vault-role\": \"test-role\"}}",
		alias_name_source=serviceaccount_uid
	)


Read A Role
-----------

Source reference: :py:meth:`hvac.api.auth_methods.Kubernetes.read_role`

.. code:: python

    import hvac
    from hvac.api.auth_methods import Kubernetes

    client = Client(url=url, verify=certificate_path)

    read_role_response = Kubernetes(client.adapter).read_role(
        name=role_name,
    )

    print(f'Policies for role "{role_name}": {",".join(read_role_response["policies"])}')

List Roles
----------

Source reference: :py:meth:`hvac.api.auth_methods.Kubernetes.list_roles`

.. code:: python

    import hvac
    from hvac.api.auth_methods import Kubernetes

    client = Client(url=url, verify=certificate_path)

    roles = Kubernetes(client.adapter).list_roles()
    print(f"The following Kubernetes auth roles are configured: {','.join(roles['keys'])}")

Delete A Role
-------------

Source reference: :py:meth:`hvac.api.auth_methods.Kubernetes.delete_role`

.. code:: python

    import hvac
    from hvac.api.auth_methods import Kubernetes

    client = Client(url=url, verify=certificate_path)

    Kubernetes(client.adapter).delete_role()
