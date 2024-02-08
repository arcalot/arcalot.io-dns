import doctest
import json
import unittest
from unittest import mock

import gandi_dns_plugin
from arcaflow_plugin_sdk import schema
from gandi_dns_plugin import SetDNSZoneInput, SetDNSZoneOutput, AccessDeniedError, BadAuthenticationError, \
    UnexpectedResponse, ConnectionFailed


class SerializationTest(unittest.TestCase):
    def test_input(self):
        schema.test_object_serialization(SetDNSZoneInput(
            api_key="asdf",
            domain="arcalot.io",
            request=gandi_dns_plugin.PutDomainRecordsRequest(
                items=[]
            )
        ))
        schema.test_object_serialization(SetDNSZoneOutput(
            "DNS update successful"
        ))
        schema.test_object_serialization(AccessDeniedError(
            object="HTTPForbidden",
            cause="Forbidden",
            code=403,
            message="Access was denied to this resource."
        ))
        schema.test_object_serialization(BadAuthenticationError(
            object="HTTPForbidden",
            cause="Forbidden",
            code=403,
            message="Access was denied to this resource."
        ))
        schema.test_object_serialization(UnexpectedResponse(
            500,
            "Internal Server Error"
        ))
        schema.test_object_serialization(ConnectionFailed(
            "Connection failed"
        ))


class MockResponse:
    def __init__(self, json_data, status_code):
        self.json_data = json_data
        self.status_code = status_code

    def json(self):
        return self.json_data


def mock_api_key_failure(*args, **kwargs):
    return MockResponse({
        "object": "HTTPForbidden",
        "cause": "Forbidden",
        "code": 401,
        "message": "Access was denied to this resource."
    }, 401)


def mock_access_denied(*args, **kwargs):
    return MockResponse({
        "object": "HTTPForbidden",
        "cause": "Forbidden",
        "code": 403,
        "message": "Access was denied to this resource."
    }, 403)


def mock_connection_failed(*args, **kwargs):
    raise Exception("Connection failed")


def mock_expect_no_zones(*args, **kwargs):
    if kwargs["headers"]["Authorization"] != "Apikey asdf":
        return MockResponse({
            "object": "HTTPForbidden",
            "cause": "Forbidden",
            "code": 403,
            "message": "Access was denied to this resource."
        }, 403)
    data = json.loads(args[0])
    if data["items"]:
        return MockResponse({
            "object": "Items",
            "cause": "Not an empty item",
            "code": 400,
            "message": "Access was denied to this resource."
        }, 400)
    return SetDNSZoneOutput(
        "DNS update successful"
    )


class RequestTests(unittest.TestCase):
    @mock.patch('requests.put', side_effect=mock_api_key_failure)
    def test_bad_api_key(self, m):
        output_id, output_data = gandi_dns_plugin.set_dns_zone(
            run_id = "ci",
            params = gandi_dns_plugin.SetDNSZoneInput(
                api_key="asdf",
                domain="arcalot.io",
                request=gandi_dns_plugin.PutDomainRecordsRequest(
                    items=[]
                )
            )
        )
        self.assertEqual(output_id, "bad_authentication")

    @mock.patch('requests.put', side_effect=mock_access_denied)
    def test_access_denied(self, m):
        output_id, output_data = gandi_dns_plugin.set_dns_zone(
            run_id = "ci",
            params = gandi_dns_plugin.SetDNSZoneInput(
                api_key="asdf",
                domain="arcalot.io",
                request=gandi_dns_plugin.PutDomainRecordsRequest(
                    items=[]
                )
            )
        )
        self.assertEqual(output_id, "access_denied")

    @mock.patch('requests.put', side_effect=mock_connection_failed)
    def test_connection_failed(self, m):
        output_id, output_data = gandi_dns_plugin.set_dns_zone(
            run_id = "ci",
            params = gandi_dns_plugin.SetDNSZoneInput(
                api_key="asdf",
                domain="arcalot.io",
                request=gandi_dns_plugin.PutDomainRecordsRequest(
                    items=[]
                )
            )
        )
        self.assertEqual(output_id, "connection_failed")


def load_tests(loader, tests, ignore):
    """
    This function adds the doctests to the discovery process.
    """
    tests.addTests(doctest.DocTestSuite(gandi_dns_plugin))
    return tests


if __name__ == '__main__':
    unittest.main()
