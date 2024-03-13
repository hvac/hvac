import logging
from unittest import TestCase

from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestInit(HvacIntegrationTestCase, TestCase):
    def test_read_init_status(self):
        read_response = self.client.sys.read_init_status()
        logging.debug("read_response: %s" % read_response)
        self.assertTrue(expr=read_response["initialized"])

    def test_is_initialized(self):
        is_initialized_response = self.client.sys.is_initialized()
        logging.debug("is_initialized_response: %s" % is_initialized_response)
        self.assertTrue(expr=is_initialized_response)
