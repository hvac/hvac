#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Gcp methods module."""
from hvac.api.vault_api_base import VaultApiBase


DEFAULT_MOUNT_POINT = ''


class Gcp(VaultApiBase):
    """Google Cloud Secrets Engine (API).
    
    Reference: https://www.vaultproject.io/api/secret/gcp/index.html
    """
    
    def write_config(self, credentials="", ttl=0 || string:"0s", max_ttl=0 || string:"0s", mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint configures shared information for the secrets engine.
        
        Supported methods:
            POST: /{mount_point}/config. Produces: 204 (empty body)
        
        
        :param credentials: 
        :type credentials: str | unicode
        :param ttl: – Specifies default config TTL for long-lived credentials
            (i.e. service account keys). Accepts integer number of seconds or Go duration format string.
        :type ttl: int
        :param max_ttl: Specifies the maximum config TTL for long-lived credentials
            (i.e. service account keys). Accepts integer number of seconds or Go duration format string.**
        :type max_ttl: int
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the write_config request.
        :rtype: requests.Response
        """
        params = {
            'credentials': credentials,
            'ttl': ttl,
            'max_ttl': max_ttl,
        }
        api_path = '/v1/{mount_point}/config'.format(mount_point=mount_point)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def read_config(self, name, project, bindings, secret_type="access_token", token_scopes=None, mount_point=DEFAULT_MOUNT_POINT):
        """
        Credentials will be omitted from returned data.
        
        Supported methods:
            GET: /{mount_point}/config. Produces: 200 application/json
        
        
        :param name: Required. Name of the role. Cannot be updated.
        :type name: str | unicode
        :param project: Name of the GCP project that this roleset's service account will belong to. Cannot be updated.
        :type project: str | unicode
        :param bindings: Bindings configuration string (expects HCL or JSON format in raw or base64-encoded string)
        :type bindings: str | unicode
        :param secret_type: Cannot be updated.
        :type secret_type: str | unicode
        :param token_scopes: sets only)
        :type token_scopes: array
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the read_config request.
        :rtype: requests.Response
        """
        params = {
            'name': name,
            'project': project,
            'bindings': bindings,
            'secret_type': secret_type,
            'token_scopes': token_scopes,
        }
        api_path = '/v1/{mount_point}/config'.format(mount_point=mount_point)
        return self._adapter.get(
            url=api_path,
            json=params,
        )

    def create_or_update_roleset(self, name, project, bindings, secret_type="access_token", token_scopes=None, mount_point=DEFAULT_MOUNT_POINT):
        """
        This method allows you to create a roleset or update an existing roleset. See roleset docs for the GCP secrets backend
        to learn more about what happens when you create or update a roleset.
        
        Supported methods:
            POST: /{mount_point}/roleset/:name. Produces: 204 (empty body)
        
        
        :param name: Required. Name of the role. Cannot be updated.
        :type name: str | unicode
        :param project: Name of the GCP project that this roleset's service account will belong to. Cannot be updated.
        :type project: str | unicode
        :param bindings: Bindings configuration string (expects HCL or JSON format in raw or base64-encoded string)
        :type bindings: str | unicode
        :param secret_type: Cannot be updated.
        :type secret_type: str | unicode
        :param token_scopes: sets only)
        :type token_scopes: array
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the create_or_update_roleset request.
        :rtype: requests.Response
        """
        params = {
            'name': name,
            'project': project,
            'bindings': bindings,
            'secret_type': secret_type,
            'token_scopes': token_scopes,
        }
        api_path = '/v1/{mount_point}/roleset/:name'.format(mount_point=mount_point)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def rotate_roleset_account(self, roleset, mount_point=DEFAULT_MOUNT_POINT):
        """
        This will rotate the service account this roleset uses to generate secrets.
        (this also replaces the key access_token roleset). This can be used to invalidate
        old secrets generated by the roleset or fix issues if a roleset's service account
        (and/or keys) was changed outside of Vault (i.e. through GCP APIs/cloud console).
        
        Supported methods:
            POST: /{mount_point}/roleset/:name/rotate. Produces: 204 (empty body)`
        
        
        :param roleset: generate access_token under.
        :type roleset: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the rotate_roleset_account request.
        :rtype: requests.Response
        """
        params = {
            'roleset': roleset,
        }
        api_path = '/v1/{mount_point}/roleset/:name/rotate'.format(mount_point=mount_point)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def rotate_roleset_account_key_access_token_roleset_only(self, roleset, mount_point=DEFAULT_MOUNT_POINT):
        """
        This will rotate the service account key this roleset uses to generate
        access tokens. This does not recreate the roleset service account.
        
        Supported methods:
            POST: /{mount_point}/roleset/:name/rotate-key. Produces: 204 (empty body)`
        
        
        :param roleset: generate access_token under.
        :type roleset: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the rotate_roleset_account_key_access_token_roleset_only request.
        :rtype: requests.Response
        """
        params = {
            'roleset': roleset,
        }
        api_path = '/v1/{mount_point}/roleset/:name/rotate-key'.format(mount_point=mount_point)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def read_roleset(self, roleset, mount_point=DEFAULT_MOUNT_POINT):
        """
        Generates an OAuth2 token with the scopes defined on the roleset. This OAuth access token can
        be used in GCP API calls, e.g. curl -H "Authorization: Bearer $TOKEN" ...
        
        Supported methods:
            GET: /{mount_point}/roleset/:name. Produces: 200 application/json
        
        
        :param roleset: generate access_token under.
        :type roleset: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the read_roleset request.
        :rtype: requests.Response
        """
        params = {
            'roleset': roleset,
        }
        api_path = '/v1/{mount_point}/roleset/:name'.format(mount_point=mount_point)
        return self._adapter.get(
            url=api_path,
            json=params,
        )

    def list_rolesets(self, roleset, mount_point=DEFAULT_MOUNT_POINT):
        """
        Generates an OAuth2 token with the scopes defined on the roleset. This OAuth access token can
        be used in GCP API calls, e.g. curl -H "Authorization: Bearer $TOKEN" ...
        
        Supported methods:
            LIST: /{mount_point}/rolesets. Produces: 200 application/json
        
        
        :param roleset: generate access_token under.
        :type roleset: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the list_rolesets request.
        :rtype: requests.Response
        """
        params = {
            'roleset': roleset,
        }
        api_path = '/v1/{mount_point}/rolesets'.format(mount_point=mount_point)
        return self._adapter.list(
            url=api_path,
            json=params,
        )

    def generate_secret_iam_service_account_creds_oauth2_access_token(self, roleset, mount_point=DEFAULT_MOUNT_POINT):
        """
        Generates an OAuth2 token with the scopes defined on the roleset. This OAuth access token can
        be used in GCP API calls, e.g. curl -H "Authorization: Bearer $TOKEN" ...
        
        Supported methods:
            GET: POST. Produces: /gcp/token/:roleset
        
        
        :param roleset: generate access_token under.
        :type roleset: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the generate_secret_iam_service_account_creds_oauth2_access_token request.
        :rtype: requests.Response
        """
        params = {
            'roleset': roleset,
        }
        api_path = '/v1POST'.format(mount_point=mount_point)
        return self._adapter.get(
            url=api_path,
            json=params,
        )

    def generate_secret_iam_service_account_creds_service_account_key(self, roleset, key_algorithm="KEY_ALG_RSA_2048", key_type=TYPE_GOOGLE_CREDENTIALS_FILE, mount_point=DEFAULT_MOUNT_POINT):
        """
        If using GET ('read'), the  optional parameters will be set to their defaults. Use POST if you
        want to specify different values for these params.
        
        Supported methods:
            GET: POST. Produces: /gcp/key/:roleset
        
        
        :param roleset: generate key under.
        :type roleset: str | unicode
        :param key_algorithm: 
        :type key_algorithm: str | unicode
        :param key_type: 
        :type key_type: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the generate_secret_iam_service_account_creds_service_account_key request.
        :rtype: requests.Response
        """
        params = {
            'roleset': roleset,
            'key_algorithm': key_algorithm,
            'key_type': key_type,
        }
        api_path = '/v1POST'.format(mount_point=mount_point)
        return self._adapter.get(
            url=api_path,
            json=params,
        )
