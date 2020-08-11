class GoogleIAP:
    """
    This class contains all of the code to authentication against a vault instance secured by Google IAP.
    NOTE: This authentication method works when leveraging a service account
    Requirements:
    1. Have your GOOGLE_APPLICATION_CREDENTAILS varaible configured with the service account you will be authenticating with
    2. The service account must have the following permission: roles/iam.serviceAccountTokenCreator
        This is required to create the JWT that is returned

    Currently supports authentication via service accounts
    """
    def __init__(self):
        self.proxy_id_token = None
        self.client_id = None

    def add_payload(self, payload):
        """
        Standard function for all plugins to add the content of the advanced_proxy["payload"] into plugin.

        This function will crape thr content os the payload for the values we require
        :param payload:
        :return:
        """
        try:
            self.client_id = payload["client_id"]
        except KeyError:
            print("A required payload K/V pair is missing: client_id\n"
                  "This KV pair is used to generates the Google-issued OpenID Connect token")
    @staticmethod
    def print_modules_note_installed(e):
        print_statement = f"""
        Looks like there was an error importing google.oauth2 library. Versions in print statements were captured at time of development
        To install google.oauth2 library use the following command:
        pip install google-auth-oauthlib==0.4.1

        To install the base google.auth package please use the following command
        pip install google-auth==1.20.1
        Exception: {e}
        """
        print(print_statement)

    def generate_auth_token(self):
        """
        Generate a valid Google-issued OpenID Connect token for the service account
        :return:
        """
        if self.client_id is None:
            print("No client_id was passed in the payload during client instantiation. Unable to generate Google-issued OpenID Connect token")
            return None
        try:
            from google.oauth2 import id_token
            from google.auth.transport.requests import Request
            self.proxy_id_token = id_token.fetch_id_token(Request(), self.client_id)
            return f"Bearer {self.proxy_id_token}"
        except Exception as e:
            self.print_modules_note_installed(e=e)
            return None


class ProxyRouter:
    def __init__(self, advanced_proxy):
        """
        The proxy router will provide a plugable advanced proxy mechanism for Vault.

        :param advanced_proxy: Type: Dict
        :param advanced_proxy:  a dictionary with two keys needs to be passed
        Example:
        {
            "provider":"google", # The name of the plugin you wish to use
            "payload": {"client_id":"my-gcp-iap-client-id-545435345345345345345"}  # Custom dict to pass to your plugin
        }


        Usage:
                advanced_proxy = {
            "provider": "google",
            "payload": {
                "client_id": "my-gcp-iap-client-id-545435345345345345345"
            }
        }
        self.client = hvac.Client(url=self.VAULT_URL, namespace='myco', advanced_proxies=advanced_proxy)
        """
        self.selected_proxy_configuration = None

        # This will need to be modified as more advanced proxy plugins become available
        self.ADVANCED_PROXIES = {
            "google": GoogleIAP,
        }

        try:
            provider = advanced_proxy.get("provider", None)
            self.get_proxy_configuration(advanced_proxy=provider)
        except AttributeError:
            print("No provider key was passed into advanced_proxy dict")
            self.get_proxy_configuration(advanced_proxy=None)

        try:
            payload = advanced_proxy.get("payload", None)
            self.add_payload_to_plugin(payload)
        except AttributeError:
            print("No payload key was passed into advanced_proxy dict")

    def get_proxy_configuration(self, advanced_proxy):
        """
        Instantiates the advanced proxy object
        :param advanced_proxy: key for self.ADVANCED_PROXIES
        :return:
        """
        if advanced_proxy is None:
            self.selected_proxy_configuration = None
        else:
            self.selected_proxy_configuration = self.ADVANCED_PROXIES.get(advanced_proxy, None)()

    def add_payload_to_plugin(self, payload):
        self.selected_proxy_configuration.add_payload(payload)

    def get_request_authorization_header(self):
        """
        :return: Returns a valid Bearer header for advance proxy
        """
        if self.selected_proxy_configuration is not None:
            return self.selected_proxy_configuration.generate_auth_token()
        else:
            return None
