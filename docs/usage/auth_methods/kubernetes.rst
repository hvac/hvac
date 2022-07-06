Kubernetes
==========

Authentication
--------------

.. code:: python

    # Kubernetes (from k8s pod)
    f = open('/var/run/secrets/kubernetes.io/serviceaccount/token')
    jwt = f.read()
    client.auth.kubernetes.login("example", jwt)
