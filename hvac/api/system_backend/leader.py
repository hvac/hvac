from hvac.api.system_backend.system_backend_mixin import SystemBackendMixin
from hvac.exceptions import LeaderNotFoundError
import time
import logging

logger = logging.getLogger(__name__)


class Leader(SystemBackendMixin):
    def read_leader_status(self):
        """Read the high availability status and current leader instance of Vault.

        Supported methods:
            GET: /sys/leader. Produces: 200 application/json

        :return: The JSON response of the request.
        :rtype: dict
        """
        api_path = "/v1/sys/leader"
        return self._adapter.get(
            url=api_path,
        )

    def step_down(self):
        """Force the node to give up active status.

        When executed against a non-active node, i.e. a standby or performance
        standby node, the request will be forwarded to the active node.
        Note that the node will sleep for ten seconds before attempting to grab
        the active lock again, but if no standby nodes grab the active lock in
        the interim, the same node may become the active node again. Requires a
        token with root policy or sudo capability on the path.

        :return: The JSON response of the request.
        :rtype: dict
        """
        api_path = "/v1/sys/step-down"
        return self._adapter.put(
            url=api_path,
        )

    def get_leader(self, retries=3, interval=5):
        """
        Check a list of Vault servers' /sys/leader status and return the leader node.

        Parameters:
            retries (int): Number of retries for each server. Default is 3.
            interval (int): Time in seconds between retries. Default is 5 seconds.

        Returns:
            str: The leader address of the active Vault node.
        """

        for uri in self._adapter.cluster_uri:
            for attempt in range(retries):
                try:
                    self._adapter.base_uri = uri
                    response = self.read_leader_status()

                    if response.get("leader_address"):
                        return response["leader_address"]

                except Exception as e:
                    logger.warning(f"Error connecting to {uri}: {e}")

                if attempt < retries - 1:
                    time.sleep(interval)

        raise LeaderNotFoundError("No leader found in the cluster URL list")
