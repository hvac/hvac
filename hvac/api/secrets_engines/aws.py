#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Aws methods module."""
from hvac.api.vault_api_base import VaultApiBase


DEFAULT_MOUNT_POINT = ''


class Aws(VaultApiBase):
    """AWS Secrets Engine (API).
    
    Reference: https://www.vaultproject.io/api/secret/aws/index.html
    """
    
    def configure_root_iam_credentials(self, access_key, secret_key, region, iam_endpoint, sts_endpoint, max_retries=-1, mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint configures the root IAM credentials to communicate with AWS. There
        are multiple ways to pass root IAM credentials to the Vault server, specified
        below with the highest precedence first. If credentials already exist, this will
        overwrite them.
        
        Supported methods:
            POST: /{mount_point}/config/root. Produces: 204 (empty body)
        
        
        :param access_key: Specifies the AWS access key ID.
        :type access_key: str | unicode
        :param secret_key: the AWS secret access key.
        :type secret_key: str | unicode
        :param region: that order.
        :type region: str | unicode
        :param iam_endpoint: a custom HTTP IAM endpoint to use.
        :type iam_endpoint: str | unicode
        :param sts_endpoint: a custom HTTP STS endpoint to use.
        :type sts_endpoint: str | unicode
        :param max_retries: falls back to the AWS SDK's default
            behavior.
        :type max_retries: int
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the configure_root_iam_credentials request.
        :rtype: requests.Response
        """
        params = {
            'access_key': access_key,
            'secret_key': secret_key,
            'region': region,
            'iam_endpoint': iam_endpoint,
            'sts_endpoint': sts_endpoint,
            'max_retries': max_retries,
        }
        api_path = '/v1/{mount_point}/config/root'.format(mount_point=mount_point)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def rotate_root_iam_credentials(self, lease, lease_max, mount_point=DEFAULT_MOUNT_POINT):
        """
        When you have configured Vault with static credentials, you can use this
        endpoint to have Vault rotate the access key it used. Note that, due to AWS
        eventual consistency, after calling this endpoint, subsequent calls from Vault
        to AWS may fail for a few seconds until AWS becomes consistent again.
        
        Supported methods:
            POST: /{mount_point}/config/rotate-root. Produces: 200 application/json
        
        
        :param lease: Specifies the lease value provided as a
            string duration with time suffix. "h" (hour) is the largest suffix.
        :type lease: str | unicode
        :param lease_max: the maximum lease value
            provided as a string duration with time suffix. "h" (hour) is the largest
            suffix.
        :type lease_max: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the rotate_root_iam_credentials request.
        :rtype: requests.Response
        """
        params = {
            'lease': lease,
            'lease_max': lease_max,
        }
        api_path = '/v1/{mount_point}/config/rotate-root'.format(mount_point=mount_point)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def configure_lease(self, lease, lease_max, mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint configures lease settings for the AWS secrets engine. It is
        optional, as there are default values for lease and lease_max.
        
        Supported methods:
            POST: /{mount_point}/config/lease. Produces: 204 (empty body)
        
        
        :param lease: Specifies the lease value provided as a
            string duration with time suffix. "h" (hour) is the largest suffix.
        :type lease: str | unicode
        :param lease_max: the maximum lease value
            provided as a string duration with time suffix. "h" (hour) is the largest
            suffix.
        :type lease_max: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the configure_lease request.
        :rtype: requests.Response
        """
        params = {
            'lease': lease,
            'lease_max': lease_max,
        }
        api_path = '/v1/{mount_point}/config/lease'.format(mount_point=mount_point)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def read_lease(self, name, credential_type, policy_document, default_sts_ttl, max_sts_ttl, role_arns=None, policy_arns=None, mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint returns the current lease settings for the AWS secrets engine.
        
        Supported methods:
            GET: /{mount_point}/config/lease. Produces: 200 application/json
        
        
        :param name: the name of the role to create. This
            is part of the request URL.
        :type name: str | unicode
        :param credential_type: 
        :type credential_type: str | unicode
        :param policy_document: the policy document will
            act as a filter on what the credentials can do.
        :type policy_document: str | unicode
        :param default_sts_ttl: 
        :type default_sts_ttl: str | unicode
        :param max_sts_ttl: 
        :type max_sts_ttl: str | unicode
        :param role_arns: otherwise. This is a comma-separated string or JSON array.
        :type role_arns: list
        :param policy_arns: be specified. This is a
            comma-separated string or JSON array.
        :type policy_arns: list
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the read_lease request.
        :rtype: requests.Response
        """
        params = {
            'name': name,
            'credential_type': credential_type,
            'policy_document': policy_document,
            'default_sts_ttl': default_sts_ttl,
            'max_sts_ttl': max_sts_ttl,
            'role_arns': role_arns,
            'policy_arns': policy_arns,
        }
        api_path = '/v1/{mount_point}/config/lease'.format(mount_point=mount_point)
        return self._adapter.get(
            url=api_path,
            json=params,
        )

    def create_or_update_role(self, name, credential_type, policy_document, default_sts_ttl, max_sts_ttl, role_arns=None, policy_arns=None, mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint creates or updates the role with the given name. If a role with
        the name does not exist, it will be created. If the role exists, it will be
        updated with the new attributes.
        
        Supported methods:
            POST: /{mount_point}/roles/:name. Produces: 204 (empty body)
        
        
        :param name: the name of the role to create. This
            is part of the request URL.
        :type name: str | unicode
        :param credential_type: 
        :type credential_type: str | unicode
        :param policy_document: the policy document will
            act as a filter on what the credentials can do.
        :type policy_document: str | unicode
        :param default_sts_ttl: 
        :type default_sts_ttl: str | unicode
        :param max_sts_ttl: 
        :type max_sts_ttl: str | unicode
        :param role_arns: otherwise. This is a comma-separated string or JSON array.
        :type role_arns: list
        :param policy_arns: be specified. This is a
            comma-separated string or JSON array.
        :type policy_arns: list
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the create_or_update_role request.
        :rtype: requests.Response
        """
        params = {
            'name': name,
            'credential_type': credential_type,
            'policy_document': policy_document,
            'default_sts_ttl': default_sts_ttl,
            'max_sts_ttl': max_sts_ttl,
            'role_arns': role_arns,
            'policy_arns': policy_arns,
        }
        api_path = '/v1/{mount_point}/roles/:name'.format(mount_point=mount_point)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def read_role(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint queries an existing role by the given name. If the role does not
        exist, a 404 is returned.
        
        Supported methods:
            GET: /{mount_point}/roles/:name. Produces: 200 application/json
        
        
        :param name: the name of the role to read. This
            is part of the request URL.
        :type name: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the read_role request.
        :rtype: requests.Response
        """
        params = {
            'name': name,
        }
        api_path = '/v1/{mount_point}/roles/:name'.format(mount_point=mount_point)
        return self._adapter.get(
            url=api_path,
            json=params,
        )

    def list_roles(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint lists all existing roles in the secrets engine.
        
        Supported methods:
            LIST: /{mount_point}/roles. Produces: 200 application/json
        
        
        :param name: the name of the role to delete. This
            is part of the request URL.
        :type name: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the list_roles request.
        :rtype: requests.Response
        """
        params = {
            'name': name,
        }
        api_path = '/v1/{mount_point}/roles'.format(mount_point=mount_point)
        return self._adapter.list(
            url=api_path,
            json=params,
        )

    def delete_role(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint deletes an existing role by the given name. If the role does not
        exist, a 404 is returned.
        
        Supported methods:
            DELETE: /{mount_point}/roles/:name. Produces: 204 (empty body)
        
        
        :param name: the name of the role to delete. This
            is part of the request URL.
        :type name: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the delete_role request.
        :rtype: requests.Response
        """
        params = {
            'name': name,
        }
        api_path = '/v1/{mount_point}/roles/:name'.format(mount_point=mount_point)
        return self._adapter.delete(
            url=api_path,
            json=params,
        )

    def generate_credentials(self, name, role_arn, ttl="3600s", method='GET', mount_point=DEFAULT_MOUNT_POINT):
        """
        This endpoint generates credentials based on the named role. This role must be
        created before queried.
        
        
        :param name: the name of the role to generate
            credentials against. This is part of the request URL.
        :type name: str | unicode
        :param role_arn: Must match one of the allowed role ARNs in
            the Vault role. Optional if the Vault role only allows a single AWS role ARN;
            required otherwise.
        :type role_arn: str | unicode
        :param ttl: types) for more details.
        :type ttl: str | unicode
        :param method: Supported methods:
            GET: /{mount_point}/creds/:name. Produces: 200 application/json
            GET: /{mount_point}/sts/:name. Produces: 200 application/json
        :type method: str | unicode
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the generate_credentials request.
        :rtype: requests.Response
        """
        params = {
            'name': name,
            'role_arn': role_arn,
            'ttl': ttl,
        }
        
        if method == 'GET':
            api_path = '/v1/{mount_point}/creds/:name'.format(mount_point=mount_point)
            return self._adapter.get(
                url=api_path,
                json=params,
            )
        
        elif method == 'GET':
            api_path = '/v1/{mount_point}/creds/:name'.format(mount_point=mount_point)
            return self._adapter.get(
                url=api_path,
                json=params,
            )
        