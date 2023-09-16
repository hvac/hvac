import hmac
from datetime import datetime, timezone
from hashlib import sha256
import requests


class SigV4Auth:
    def __init__(self, access_key, secret_key, session_token=None, region="us-east-1"):
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token
        self.region = region

    def add_auth(self, request):
        timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        request.headers["X-Amz-Date"] = timestamp

        if self.session_token:
            request.headers["X-Amz-Security-Token"] = self.session_token

        # https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
        canonical_headers = "".join(
            f"{k.lower()}:{request.headers[k]}\n" for k in sorted(request.headers)
        )
        signed_headers = ";".join(k.lower() for k in sorted(request.headers))
        payload_hash = sha256(request.body.encode("utf-8")).hexdigest()
        canonical_request = "\n".join(
            [request.method, "/", "", canonical_headers, signed_headers, payload_hash]
        )

        # https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
        algorithm = "AWS4-HMAC-SHA256"
        credential_scope = "/".join(
            [timestamp[0:8], self.region, "sts", "aws4_request"]
        )
        canonical_request_hash = sha256(canonical_request.encode("utf-8")).hexdigest()
        string_to_sign = "\n".join(
            [algorithm, timestamp, credential_scope, canonical_request_hash]
        )

        # https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
        key = f"AWS4{self.secret_key}".encode()
        key = hmac.new(key, timestamp[0:8].encode("utf-8"), sha256).digest()
        key = hmac.new(key, self.region.encode("utf-8"), sha256).digest()
        key = hmac.new(key, b"sts", sha256).digest()
        key = hmac.new(key, b"aws4_request", sha256).digest()
        signature = hmac.new(key, string_to_sign.encode("utf-8"), sha256).hexdigest()

        # https://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html
        authorization = f"{algorithm} Credential={self.access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
        request.headers["Authorization"] = authorization


def generate_sigv4_auth_request(header_value=None):
    """Helper function to prepare a AWS API request to subsequently generate a "AWS Signature Version 4" header.

    :param header_value: Vault allows you to require an additional header, X-Vault-AWS-IAM-Server-ID, to be present
        to mitigate against different types of replay attacks. Depending on the configuration of the AWS auth
        backend, providing a argument to this optional parameter may be required.
    :type header_value: str
    :return: A PreparedRequest instance, optionally containing the provided header value under a
        'X-Vault-AWS-IAM-Server-ID' header name pointed to AWS's simple token service with action "GetCallerIdentity"
    :rtype: requests.PreparedRequest
    """
    request = requests.Request(
        method="POST",
        url="https://sts.amazonaws.com/",
        headers={
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
            "Host": "sts.amazonaws.com",
        },
        data="Action=GetCallerIdentity&Version=2011-06-15",
    )

    if header_value:
        request.headers["X-Vault-AWS-IAM-Server-ID"] = header_value

    return request.prepare()
