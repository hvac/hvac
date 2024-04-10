#!/usr/bin/env python
from hvac import utils
from hvac.api.system_backend.system_backend_mixin import SystemBackendMixin


class Tools(SystemBackendMixin):
    def generate_random_bytes(
        self, n_bytes=None, output_format=None, source=None
    ):
        """Return high-quality random bytes of the specified length.

        Supported methods:
            POST: /sys/tools/random(/:source)(/:bytes). Produces: 200 application/json

        :param n_bytes: Specifies the number of bytes to return. This value can be specified either in the request body,
            or as a part of the URL.
        :type n_bytes: int
        :param output_format: Specifies the output encoding. Valid options are hex or base64.
        :type output_format: str | unicode
        :param source: Specifies the source of the requested bytes. ``platform``, the default, 
            sources bytes from the platform's entropy source. ``seal`` sources from entropy augmentation (enterprise only). 
            ``all`` mixes bytes from all available sources.
        :type source: str | unicode
        :return: The JSON response of the request.
        :rtype: dict
        """
        params = utils.remove_nones(
            {
                "bytes": n_bytes,
                "format": output_format,
            }
        )

        if source is None:
            api_path = "/v1/sys/tools/random"
        else:
            api_path = utils.format_url("/v1/sys/tools/random/{source}", source=source)

        return self._adapter.post(
            url=api_path,
            json=params,
        )
