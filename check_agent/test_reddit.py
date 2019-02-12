from nose.plugins.attrib import attr
from tests.checks.common import AgentCheckTest
import unittest
from checks import AgentCheck
import requests

CONFIG = {
    "instances": [{
        "refresh_token": "{{ REPLACE ME WITH AN ACCOUNTS REFRESH TOKEN -- SEE README }}"
    }],
    "init_config": {
        "min_collection_interval": 120,
        "default_timeout": 5,
        "client_id": "MkcLNaOSOME8mA",
        "client_agent": "sts-agent"
    }
}

HTTP_ERROR_CONFIG = {
    "instances": [{
        "refresh_token": "INTENTIONALLY_BOGUS_REFRESH_TOKEN"
    }],
    "init_config": {
        "min_collection_interval": 120,
        "default_timeout": 5,
        "client_id": "MkcLNaOSOME8mA",
        "client_agent": "sts-agent"
    }
}

NO_REFRESH_TOKEN_CONFIG = {
    "instances": [{}],
    "init_config": {
        "min_collection_interval": 120,
        "default_timeout": 5,
        "client_id": "MkcLNaOSOME8mA",
        "client_agent": "sts-agent"
    }
}


@attr(requires="reddit")
class RedditCheckTest(AgentCheckTest):
    CHECK_NAME = "reddit"

    def test_check(self):
        self.run_check(CONFIG)

        self.assertServiceCheck(self.CHECK_NAME, status=AgentCheck.OK, count=1)
        self.assertServiceCheck(self.CHECK_NAME, status=AgentCheck.WARNING, count=0)
        self.assertServiceCheck(self.CHECK_NAME, status=AgentCheck.CRITICAL, count=0)

    def test_invalid_refresh_token(self):
        self.assertRaises(requests.exceptions.HTTPError, self.run_check, HTTP_ERROR_CONFIG)

    def test_no_refresh_token(self):
        self.assertRaises(requests.exceptions.HTTPError, self.run_check, HTTP_ERROR_CONFIG)


if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(RedditCheckTest)
    unittest.TextTestRunner(verbosity=3).run(suite)
