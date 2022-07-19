Kubernetes
==========

Authentication
--------------

.. code:: python

    from hvac import Client
    from hvac.api.auth_methods import Kubernetes

    client = Client(url=url, verify=certificate_path)

    # Kubernetes (from k8s pod)
    f = open('/var/run/secrets/kubernetes.io/serviceaccount/token')
    jwt = f.read()
    Kubernetes(client.adapter).login(role=role, jwt=jwt)
