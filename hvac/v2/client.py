class ClientFeature(object):
    """
    Redirects calls to client methods to the parent client
    """

    def __init__(self, client):
        self.client = client

    def _post(self, *args, **kwargs):
        return self.client._post(*args, **kwargs)

    def _read(self, *args, **kwargs):
        return self.client.read(*args, **kwargs)

    def _delete(self, *args, **kwargs):
        return self.client.delete(*args, **kwargs)

    def _list(self, *args, **kwargs):
        return self.client.list(*args, **kwargs)
