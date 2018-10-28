#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Transit methods module."""
from hvac.api.vault_api_base import VaultApiBase


DEFAULT_MOUNT_POINT = 'transit'


class Transit(VaultApiBase):
    """Transit Secrets Engine (API).

    Reference: https://www.vaultproject.io/api/secret/transit/index.html
    """

    def create_key(self, name, convergent_encryption=False, derived=False, exportable=False, allow_plaintext_backup=False, key_type="aes256-gcm96",
                   mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint creates a new named encryption key of the specified type. The
        values set here cannot be changed after key creation.

        Supported methods:
            POST: /{mount_point}/keys/:name. Produces: 204 (empty body)


        :param name: Specifies the name of the encryption key to create. This is specified as part of the URL.
        :type name: str | unicode
        :param convergent_encryption: If enabled, the key will support convergent encryption, where the same plaintext creates the same ciphertext. This
            requires derived to be set to true. When enabled, each encryption(/decryption/rewrap/datakey) operation will derive a nonce value rather than
            randomly generate it.
        :type convergent_encryption: bool
        :param derived: Specifies if key derivation is to be used. If enabled, all encrypt/decrypt requests to this named key must provide a context which is
            used for key derivation.
        :type derived: bool
        :param exportable: Enables keys to be exportable. This allows for all the valid keys in the key ring to be exported. Once set, this cannot be disabled.
        :type exportable: bool
        :param allow_plaintext_backup: If set, enables taking backup of named key in the plaintext format. Once set, this cannot be disabled.
        :type allow_plaintext_backup: bool
        :param key_type: Specifies the type of key to create. The currently-supported types are:
            aes256-gcm96: AES-256 wrapped with GCM using a 96-bit nonce size AEAD
                (symmetric, supports derivation and convergent encryption)
            chacha20-poly1305: ChaCha20-Poly1305 AEAD (symmetric, supports
                derivation and convergent encryption)
            ed25519: ED25519 (asymmetric, supports derivation). When using
                derivation, a sign operation with the same context will derive
                the same key and signature; this is a signing analogue to
                convergent_encryption.
            ecdsa-p256: ECDSA using the P-256 elliptic curve (asymmetric)
            rsa-2048: RSA with bit size of 2048 (asymmetric)
            rsa-4096: RSA with bit size of 4096 (asymmetric)
        :type type: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the create_key request.
        :rtype: requests.Response
        """
        params = {
            'convergent_encryption': convergent_encryption,
            'derived': derived,
            'exportable': exportable,
            'allow_plaintext_backup': allow_plaintext_backup,
            'type': key_type,
        }
        api_path = '/v1/{mount_point}/keys/{name}'.format(mount_point=mount_point, name=name)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def read_key(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint returns information about a named encryption key. The keys object shows the creation time of each key version; the values are not the
        keys themselves. Depending on the type of key, different information may be returned, e.g. an asymmetric key will return its public key in a standard
        format for the type.

        Supported methods:
            GET: /{mount_point}/keys/:name. Produces: 200 application/json


        :param name: Specifies the name of the encryption key to read. This is specified as part of the URL.
        :type name: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the read_key request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/keys/{name}'.format(mount_point=mount_point, name=name)
        return self._adapter.get(
            url=api_path,
        )

    def list_keys(self, mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint returns a list of keys. Only the key names are returned (not the actual keys themselves).

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json


        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the list_keys request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/keys'.format(mount_point=mount_point)
        return self._adapter.list(
            url=api_path
        )

    def delete_key(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint deletes a named encryption key. It will no longer be possible to decrypt any data encrypted with the named key. Because this is a
        potentially catastrophic operation, the deletion_allowed tunable must be set in the key's /config endpoint.

        Supported methods:
            DELETE: /{mount_point}/keys/:name. Produces: 204 (empty body)


        :param name: Specifies the name of the encryption key to delete. This is specified as part of the URL.
        :type name: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the delete_key request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/keys/{name}'.format(mount_point=mount_point, name=name)
        return self._adapter.delete(
            url=api_path,
        )

    def update_key_configuration(self, name, min_decryption_version=0, min_encryption_version=0, deletion_allowed=False, exportable=False,
                                 allow_plaintext_backup=False, mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint allows tuning configuration values for a given key. (These values are returned during a read operation on the named key.)

        Supported methods:
            POST: /{mount_point}/keys/:name/config. Produces: 204 (empty body)


        :param min_decryption_version: Specifies the minimum version of ciphertext allowed to be decrypted. Adjusting this as part of a key rotation policy
            can prevent old copies of ciphertext from being decrypted, should they fall into the wrong hands. For signatures, this value controls the minimum
            version of signature that can be verified against. For HMACs, this controls the minimum version of a key allowed to be used as the key for
            verification.
        :type min_decryption_version: int
        :param min_encryption_version: Specifies the minimum version of the key that can be used to encrypt plaintext, sign payloads, or generate HMACs. Must
            be 0 (which will use the latest version) or a value greater or equal to min_decryption_version.
        :type min_encryption_version: int
        :param deletion_allowed: Specifies if the key is allowed to be deleted.
        :type deletion_allowed: bool
        :param exportable: Enables keys to be exportable. This allows for all the valid keys in the key ring to be exported. Once set, this cannot be disabled.
        :type exportable: bool
        :param allow_plaintext_backup: If set, enables taking backup of named key in the plaintext format. Once set, this cannot be disabled.
        :type allow_plaintext_backup: bool
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the update_key_configuration request.
        :rtype: requests.Response
        """
        params = {
            'min_decryption_version': min_decryption_version,
            'min_encryption_version': min_encryption_version,
            'deletion_allowed': deletion_allowed,
            'exportable': exportable,
            'allow_plaintext_backup': allow_plaintext_backup,
        }
        api_path = '/v1/{mount_point}/keys/{name}/config'.format(mount_point=mount_point, name=name)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def rotate_key(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint rotates the version of the named key. After rotation, new plaintext requests will be encrypted with the new version of the key. To
        upgrade ciphertext to be encrypted with the latest version of the key, use the rewrap endpoint. This is only supported with keys that support
        encryption and decryption operations.

        Supported methods:
            POST: /{mount_point}/keys/:name/rotate. Produces: 204 (empty body)


        :param name: Specifies the name of the key to read information about. This is specified as part of the URL.
        :type name: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the rotate_key request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/keys/{name}/rotate'.format(mount_point=mount_point, name=name)
        return self._adapter.post(
            url=api_path,
        )

    def export_key(self, key_type, name, version="", mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint returns the named key. The keys object shows the value of the key for each version. If version is specified, the specific version will be
        returned. If latest is provided as the version, the current key will be provided. Depending on the type of key, different information may be returned.
        The key must be exportable to support this operation and the version must still be valid.

        Supported methods:
            GET: /{mount_point}/export/:key_type/:name(/:version). Produces: 200 application/json


        :param key_type: Specifies the type of the key to export. This is specified as part of the URL. Valid values are:
            encryption-key
            signing-key
            hmac-key
        :type key_type: str | unicode
        :param name: Specifies the name of the key to read information about. This is specified as part of the URL.
        :type name: str | unicode
        :param version: Specifies the version of the key to read. If omitted, all versions of the key will be returned. This is specified as part of the URL.
            If the version is set to latest, the current key will be returned.
        :type version: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the export_key request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/export/{key_type}/{name}'.format(mount_point=mount_point, key_type=key_type, name=name)
        if version != "":
            api_path += '/:version'.format(version=version)
        return self._adapter.get(
            url=api_path,
        )

    def encrypt_data(self, name, plaintext, context="", key_version=0, nonce="", batch_input=None, type="aes256-gcm96", convergent_encryption="",
                     mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint encrypts the provided plaintext using the named key. This path supports the create and update policy capabilities as follows: if the user
        has the create capability for this endpoint in their policies, and the key does not exist, it will be upserted with default values (whether the key
        requires derivation depends on whether the context parameter is empty or not). If the user only has update capability and the key does not exist, an
        error will be returned.

        Supported methods:
            POST: /{mount_point}/encrypt/:name. Produces: 200 application/json


        :param name: Specifies the name of the encryption key to encrypt against. This is specified as part of the URL.
        :type name: str | unicode
        :param plaintext: Specifies base64 encoded plaintext to be encoded.
        :type plaintext: str | unicode
        :param context: Specifies the base64 encoded context for key derivation. This is required if key derivation is enabled for this key.
        :type context: str | unicode
        :param key_version: Specifies the version of the key to use for encryption. If not set, uses the latest version. Must be greater than or equal to the
            key's min_encryption_version, if set.
        :type key_version: int
        :param nonce: Specifies the base64 encoded nonce value. This must be provided if convergent encryption is enabled for this key and the key was
            generated with Vault 0.6.1. Not required for keys created in 0.6.2+. The value must be exactly 96 bits (12 bytes) long and the user must ensure
            that for any given context (and thus, any given encryption key) this nonce value is never reused.
        :type nonce: str | unicode
        :param batch_input: Specifies a list of items to be encrypted in a single batch. When this parameter is set, if the parameters 'plaintext', 'context'
            and 'nonce' are also set, they will be ignored. The format for the input is:
            [
                {
                    "context": "c2FtcGxlY29udGV4dA==",
                    "plaintext": "dGhlIHF1aWNrIGJyb3duIGZveA=="
                },
                {
                    "context": "YW5vdGhlcnNhbXBsZWNvbnRleHQ=",
                    "plaintext": "dGhlIHF1aWNrIGJyb3duIGZveA=="
                },
            ]
        :type batch_input: array<object>
        :param type: This parameter is required when encryption key is expected to be created. When performing an upsert operation, the type of key to create.
        :type type: str | unicode
        :param convergent_encryption: This parameter will only be used when a key is expected to be created. Whether to support convergent encryption. This is
            only supported when using a key with key derivation enabled and will require all requests to carry both a context and 96-bit (12-byte) nonce. The
            given nonce will be used in place of a randomly generated nonce. As a result, when the same context and nonce are supplied, the same ciphertext is
            generated. It is very important when using this mode that you ensure that all nonces are unique for a given context. Failing to do so will severely
            impact the ciphertext's security.
        :type convergent_encryption: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the encrypt_data request.
        :rtype: requests.Response
        """
        params = {
            'plaintext': plaintext,
            'context': context,
            'key_version': key_version,
            'nonce': nonce,
            'batch_input': batch_input,
            'type': type,
            'convergent_encryption': convergent_encryption,
        }
        api_path = '/v1/{mount_point}/encrypt/{name}'.format(mount_point=mount_point, name=name)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def decrypt_data(self, name, ciphertext, context="", nonce="", batch_input=None, mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint decrypts the provided ciphertext using the named key.

        Supported methods:
            POST: /{mount_point}/decrypt/:name. Produces: 200 application/json


        :param name: Specifies the name of the encryption key to decrypt against. This is specified as part of the URL.
        :type name: str | unicode
        :param ciphertext: the ciphertext to decrypt.
        :type ciphertext: str | unicode
        :param context: Specifies the base64 encoded context for key derivation. This is required if key derivation is enabled.
        :type context: str | unicode
        :param nonce: Specifies a base64 encoded nonce value used during encryption. Must be provided if convergent encryption is enabled for this key and the
            key was generated with Vault 0.6.1. Not required for keys created in 0.6.2+.
        :type nonce: str | unicode
        :param batch_input: Specifies a list of items to be decrypted in a single batch. When this parameter is set, if the parameters 'ciphertext', 'context'
            and 'nonce' are also set, they will be ignored. Format for the input goes like this:
            [
                {
                    "context": "c2FtcGxlY29udGV4dA==",
                    "ciphertext": "vault:v1:/DupSiSbX/ATkGmKAmhqD0tvukByrx6gmps7dVI="
                },
                {
                    "context": "YW5vdGhlcnNhbXBsZWNvbnRleHQ=",
                    "ciphertext": "vault:v1:XjsPWPjqPrBi1N2Ms2s1QM798YyFWnO4TR4lsFA="
                },
            ]
        :type batch_input: array<object>
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the decrypt_data request.
        :rtype: requests.Response
        """
        params = {
            'ciphertext': ciphertext,
            'context': context,
            'nonce': nonce,
            'batch_input': batch_input,
        }
        api_path = '/v1/{mount_point}/decrypt/{name}'.format(mount_point=mount_point, name=name)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def rewrap_data(self, name, ciphertext, context="", key_version=0, nonce="", batch_input=None, mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint rewraps the provided ciphertext using the latest version of the named key. Because this never returns plaintext, it is possible to
        delegate this functionality to untrusted users or scripts.

        Supported methods:
            POST: /{mount_point}/rewrap/:name. Produces: 200 application/json


        :param name: Specifies the name of the encryption key to re-encrypt against. This is specified as part of the URL.
        :type name: str | unicode
        :param ciphertext: Specifies the ciphertext to re-encrypt.
        :type ciphertext: str | unicode
        :param context: Specifies the base64 encoded context for key derivation. This is required if key derivation is enabled.
        :type context: str | unicode
        :param key_version: Specifies the version of the key to use for the operation. If not set, uses the latest version. Must be greater than or equal to
            the key's min_encryption_version, if set.
        :type key_version: int
        :param nonce: Specifies a base64 encoded nonce value used during encryption. Must be provided if convergent encryption is enabled for this key and the
            key was generated with Vault 0.6.1. Not required for keys created in 0.6.2+.
        :type nonce: str | unicode
        :param batch_input: Specifies a list of items to be decrypted in a single batch. When this parameter is set, if the parameters 'ciphertext', 'context'
            and 'nonce' are also set, they will be ignored. Format for the input goes like this:
            [
                {
                    "context": "c2FtcGxlY29udGV4dA==",
                    "ciphertext": "vault:v1:/DupSiSbX/ATkGmKAmhqD0tvukByrx6gmps7dVI="
                },
                {
                    "context": "YW5vdGhlcnNhbXBsZWNvbnRleHQ=",
                    "ciphertext": "vault:v1:XjsPWPjqPrBi1N2Ms2s1QM798YyFWnO4TR4lsFA="
                },
            ]
        :type batch_input: array<object>
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the rewrap_data request.
        :rtype: requests.Response
        """
        params = {
            'ciphertext': ciphertext,
            'context': context,
            'key_version': key_version,
            'nonce': nonce,
            'batch_input': batch_input,
        }
        api_path = '/v1/{mount_point}/rewrap/{name}'.format(mount_point=mount_point, name=name)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def generate_data_key(self, key_type, name, context="", nonce="", bits=256, mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint generates a new high-entropy key and the value encrypted with the named key. Optionally return the plaintext of the key as well. Whether
        plaintext is returned depends on the path; as a result, you can use Vault ACL policies to control whether a user is allowed to retrieve the plaintext
        value of a key. This is useful if you want an untrusted user or operation to generate keys that are then made available to trusted users.

        Supported methods:
            POST: /{mount_point}/datakey/:type/:name. Produces: 200 application/json


        :param key_type: Specifies the type of key to generate. If plaintext, the plaintext key will be returned along with the ciphertext. If wrapped, only the
            ciphertext value will be returned. This is specified as part of the URL.
        :type key_type: str | unicode
        :param name: Specifies the name of the encryption key to use to encrypt the datakey. This is specified as part of the URL.
        :type name: str | unicode
        :param context: Specifies the key derivation context, provided as a base64-encoded string. This must be provided if derivation is enabled.
        :type context: str | unicode
        :param nonce: Specifies a nonce value, provided as base64 encoded. Must be provided if convergent encryption is enabled for this key and the key was
            generated with Vault 0.6.1. Not required for keys created in 0.6.2+. The value must be exactly 96 bits (12 bytes) long and the user must ensure
            that for any given context (and thus, any given encryption key) this nonce value is never reused.
        :type nonce: str | unicode
        :param bits: Specifies the number of bits in the desired key. Can be 128, 256, or 512.
        :type bits: int
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the generate_data_key request.
        :rtype: requests.Response
        """
        params = {
            'context': context,
            'nonce': nonce,
            'bits': bits,
        }
        api_path = '/v1/{mount_point}/datakey/{key_type}/{name}'.format(mount_point=mount_point, key_type=key_type, name=name)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def generate_random_bytes(self, n_bytes=32, output_format="base64", mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint returns high-quality random bytes of the specified length.

        Supported methods:
            POST: /{mount_point}/random(/:bytes). Produces: 200 application/json


        :param n_bytes: Specifies the number of bytes to return. This value can be specified either in the request body, or as a part of the URL.
        :type n_bytes: int
        :param output_format: Specifies the output encoding. Valid options are hex or base64.
        :type output_format: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the generate_random_bytes request.
        :rtype: requests.Response
        """
        params = {
            'format': output_format,
        }
        api_path = '/v1/{mount_point}/random'.format(mount_point=mount_point)
        if n_bytes != 32:
            api_path += '/{n_bytes}'.format(n_bytes=n_bytes)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def hash_data(self, hash_input, algorithm="sha2-256", output_format="hex", mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint returns the cryptographic hash of given data using the specified algorithm.

        Supported methods:
            POST: /{mount_point}/hash(/:algorithm). Produces: 200 application/json


        :param input: Specifies the base64 encoded input data.
        :type input: str | unicode
        :param algorithm: Specifies the hash algorithm to use. This can also be specified as part of the URL. Currently-supported algorithms are:
            sha2-224, sha2-256, sha2-384, sha2-512
        :type algorithm: str | unicode
        :param output_format: Specifies the output encoding. This can be either hex or base64.
        :type output_format: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the hash_data request.
        :rtype: requests.Response
        """
        params = {
            'input': hash_input,
            'algorithm': algorithm,
            'format': output_format,
        }
        api_path = '/v1/{mount_point}/hash'.format(mount_point=mount_point)
        if algorithm != 'sha2-256':
            api_path += '/:algorithm'.format(algorithm=algorithm)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def generate_hmac(self, name, hash_input, key_version=0, algorithm="sha2-256", mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint returns the digest of given data using the specified hash algorithm and the named key. The key can be of any type supported by transit;
        the raw key will be marshaled into bytes to be used for the HMAC function. If the key is of a type that supports rotation, the latest (current) version
        will be used.

        Supported methods:
            POST: /{mount_point}/hmac/:name(/:algorithm). Produces: 200 application/json


        :param name: Specifies the name of the encryption key to generate hmac against. This is specified as part of the URL.
        :type name: str | unicode
        :param hash_input: Specifies the base64 encoded input data.
        :type input: str | unicode
        :param key_version: Specifies the version of the key to use for the operation. If not set, uses the latest version. Must be greater than or equal to
            the key's min_encryption_version, if set.
        :type key_version: int
        :param algorithm: Specifies the hash algorithm to use. This can also be specified as part of the URL. Currently-supported algorithms are:
            sha2-224, sha2-256, sha2-384, sha2-512
        :type algorithm: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the generate_hmac request.
        :rtype: requests.Response
        """
        params = {
            'input': hash_input,
            'key_version': key_version,
            'algorithm': algorithm,
        }
        api_path = '/v1/{mount_point}/hmac/{name}'.format(mount_point=mount_point, name=name)
        if algorithm != 'sha2-256':
            api_path += '/:algorithm'.format(algorithm=algorithm)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def sign_data(self, name, hash_input, key_version=0, hash_algorithm="sha2-256", context="", prehashed=False, signature_algorithm="pss",
                  mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint returns the cryptographic signature of the given data using the named key and the specified hash algorithm. The key must be of a type
        that supports signing.

        Supported methods:
            POST: /{mount_point}/sign/:name(/:hash_algorithm). Produces: 200 application/json


        :param name: Specifies the name of the encryption key to use for signing. This is specified as part of the URL.
        :type name: str | unicode
        :param hash_input: Specifies the base64 encoded input data.
        :type hash_input: str | unicode
        :param key_version: Specifies the version of the key to use for signing. If not set, uses the latest version. Must be greater than or equal to the
            key's min_encryption_version, if set.
        :type key_version: int
        :param hash_algorithm: Specifies the hash algorithm to use for supporting key types (notably, not including ed25519 which specifies its own hash
            algorithm). This can also be specified as part of the URL. Currently-supported algorithms are: sha2-224, sha2-256, sha2-384, sha2-512
        :type hash_algorithm: str | unicode
        :param context: Base64 encoded context for key derivation. Required if key derivation is enabled; currently only available with ed25519 keys.
        :type context: str | unicode
        :param prehashed: Set to true when the input is already hashed. If the key type is rsa-2048 or rsa-4096, then the algorithm used to hash the input
            should be indicated by the hash_algorithm parameter. Just as the value to sign should be the base64-encoded representation of the exact binary
            data you want signed, when set, input is expected to be base64-encoded binary hashed data, not hex-formatted. (As an example, on the command line,
            you could generate a suitable input via openssl dgst -sha256 -binary | base64.)
        :type prehashed: bool
        :param signature_algorithm: When using a RSA key, specifies the RSA signature algorithm to use for signing.
            Supported signature types are: pss, pkcs1v15
        :type signature_algorithm: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the sign_data request.
        :rtype: requests.Response
        """
        params = {
            'input': hash_input,
            'key_version': key_version,
            'hash_algorithm': hash_algorithm,
            'context': context,
            'prehashed': prehashed,
            'signature_algorithm': signature_algorithm,
        }
        api_path = '/v1/{mount_point}/sign/{name}'.format(mount_point=mount_point, name=name)
        if hash_algorithm != 'sha2-256':
            api_path += '/:hash_algorithm'.format(hash_algorithm=hash_algorithm)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def verify_signed_data(self, name, hash_input, hash_algorithm="sha2-256", signature="", hmac="", context="", prehashed=False, signature_algorithm="pss",
                           mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint returns whether the provided signature is valid for the given data.

        Supported methods:
            POST: /{mount_point}/verify/:name(/:hash_algorithm). Produces: 200 application/json


        :param name: Specifies the name of the encryption key that was used to generate the signature or HMAC.
        :type name: str | unicode
        :param hash_input: Specifies the base64 encoded input data.
        :type input: str | unicode
        :param hash_algorithm: Specifies the hash algorithm to use. This can also be specified as part of the URL. Currently-supported algorithms are:
            sha2-224, sha2-256, sha2-384, sha2-512
        :type hash_algorithm: str | unicode
        :param signature: Specifies the signature output from the /transit/sign function. Either this must be supplied or hmac must be supplied.
        :type signature: str | unicode
        :param hmac: Specifies the signature output from the /transit/hmac function. Either this must be supplied or signature must be supplied.
        :type hmac: str | unicode
        :param context: Base64 encoded context for key derivation. Required if key derivation is enabled; currently only available with ed25519 keys.
        :type context: str | unicode
        :param prehashed: Set to true when the input is already hashed. If the key type is rsa-2048 or rsa-4096, then the algorithm used to hash the input
            should be indicated by the hash_algorithm parameter.
        :type prehashed: bool
        :param signature_algorithm: When using a RSA key, specifies the RSA signature algorithm to use for signature verification. Supported signature types
            are: pss, pkcs1v15
        :type signature_algorithm: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the verify_signed_data request.
        :rtype: requests.Response
        """
        params = {
            'name': name,
            'input': hash_input,
            'hash_algorithm': hash_algorithm,
            'signature': signature,
            'hmac': hmac,
            'context': context,
            'prehashed': prehashed,
            'signature_algorithm': signature_algorithm,
        }
        api_path = '/v1/{mount_point}/verify/{name}'.format(mount_point=mount_point, name=name)
        if hash_algorithm != 'sha2-256':
            api_path += '/:hash_algorithm'.format(hash_algorithm=hash_algorithm)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def backup_key(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint returns a plaintext backup of a named key. The backup contains all the configuration data and keys of all the versions along with the
        HMAC key. The response from this endpoint can be used with the /restore endpoint to restore the key.

        Supported methods:
            GET: /{mount_point}/backup/:name. Produces: 200 application/json


        :param name: Name of the key.
        :type name: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the backup_key request.
        :rtype: requests.Response
        """
        api_path = '/v1/{mount_point}/backup/{name}'.format(mount_point=mount_point, name=name)
        return self._adapter.get(
            url=api_path,
        )

    def restore_key(self, backup, name, force=False, mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint restores the backup as a named key. This will restore the key
        configurations and all the versions of the named key along with HMAC keys. The
        input to this endpoint should be the output of /backup endpoint.

        Supported methods:
            POST: /{mount_point}/restore(/:name). Produces: 204 (empty body)


        :param backup:
        :type backup: str | unicode
        :param name: If set, this will be the name of the
            restored key.
        :type name: str | unicode
        :param force: If set, force the restore to proceed even if a key
            by this name already exists.
        :type force: bool
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the restore_key request.
        :rtype: requests.Response
        """
        params = {
            'backup': backup,
            'name': name,
            'force': force,
        }
        api_path = '/v1/{mount_point}/restore(/:name)'.format(mount_point=mount_point)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def trim_key(self, min_version, mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint trims older key versions setting a minimum version for the
        keyring. Once trimmed, previous versions of the key cannot be recovered.

        Supported methods:
            POST: /{mount_point}/keys/:name/trim. Produces: 200 application/json


        :param min_version: set to zero.
        :type min_version: int
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the trim_key request.
        :rtype: requests.Response
        """
        params = {
            'min_version': min_version,
        }
        api_path = '/v1/{mount_point}/keys/:name/trim'.format(mount_point=mount_point)
        return self._adapter.post(
            url=api_path,
            json=params,
        )