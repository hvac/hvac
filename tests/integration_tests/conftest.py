import pytest
import distutils
import subprocess

from tests.utils import get_config_file_path

@pytest.fixture(scope="class", autouse=True)
def test_setup(request):
    def _test_setup():
        if distutils.spawn.find_executable("docker") and distutils.spawn.find_executable("terraform"):
            print("Setting up docker/terraform")
            # We can spin up Vault inside docker and use terraform to do some base configuration
            docker_file = get_config_file_path("vault-ldap/docker-compose.yml")
            try:
                subprocess.check_call(f"docker compose -f '{docker_file}' up -d --wait vault openldap", shell=True)
            except Exception as e:
                print("Failed to setup docker/terraform for test, you must have Vault installed locally. Error: " + str(e))

    def _test_teardown():
        print("Tearing down docker/terraform")
        docker_file = get_config_file_path("vault-ldap/docker-compose.yml")
        subprocess.check_call(f"docker compose -f '{docker_file}' down vault openldap", shell=True)

    _test_teardown()
    _test_setup()
    request.addfinalizer(_test_teardown)