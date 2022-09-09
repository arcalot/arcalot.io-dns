#!/usr/bin/env python3

import enum
import json
import os
import re
import sys
import typing
from dataclasses import dataclass

import requests
from arcaflow_plugin_sdk import plugin, schema
from arcaflow_plugin_sdk.schema import ConstraintException
from requests import JSONDecodeError


def _read_local_file(filename: str) -> str:
    with open(os.path.dirname(os.path.realpath(__file__)) + "/" + filename, "r") as f:
        return f.read()


_UNIT_TIME_SECONDS = schema.Units(
    schema.Unit(
        "s",
        "s",
        "second",
        "seconds"
    ),
    {
        60: schema.Unit(
            "m",
            "m",
            "minute",
            "minutes"
        ),
        3600: schema.Unit(
            "H",
            "H",
            "hour",
            "hours"
        ),
        86400: schema.Unit(
            "d",
            "d",
            "day",
            "days"
        ),
    }
)


class RRSetType(enum.Enum):
    A = "A"
    AAAA = "AAAA"
    ALIAS = "ALIAS"
    CAA = "CAA"
    CDS = "CDS"
    CNAME = "CNAME"
    DNAME = "DNAME"
    DS = "DS"
    KEY = "KEY"
    LOC = "LOC"
    MX = "MX"
    NAPTR = "NAPTR"
    NS = "NS"
    OPENPGPKEY = "OPENPGPKEY"
    PTR = "PTR"
    RP = "RP"
    SPF = "SPF"
    SRV = "SRV"
    SSHFP = "SSHFP"
    TLSA = "TLSA"
    TXT = "TXT"
    WKS = "WKS"


@dataclass
class DNSRecord:
    rrset_name: typing.Annotated[
        str,
        schema.name("Record name"),
        schema.description("Name of the record."),
    ]
    rrset_type: typing.Annotated[
        RRSetType,
        schema.name("Record type"),
        schema.description("DNS record type."),
    ]
    rrset_values: typing.Annotated[
        typing.List[str],
        schema.name("Values"),
        schema.description("List of values for this DNS record.")
    ]
    rrset_ttl: typing.Annotated[
        int,
        schema.name("Time To Live"),
        schema.description("Time for how long this record may be cached."),
        schema.units(_UNIT_TIME_SECONDS),
        schema.min(300),
        schema.max(2592000)
    ]


@dataclass
class SetDNSZoneOutput:
    message: typing.Annotated[
        str,
        schema.name("Message"),
        schema.description("Confirmation message")
    ]


@dataclass
class PutDomainRecordsRequest:
    items: typing.Annotated[
        typing.List[DNSRecord],
        schema.name("DNS records"),
        schema.description(
            "DNS records to set on this zone. All records that are not set will be removed, except for"
            "the NS record if the remove apex NS filed is not set."
        )
    ]
    remove_apex_ns: typing.Annotated[
        bool,
        schema.name("Remove apex NS"),
        schema.name(
            "The default behavior is to keep the NS records on the zone if no NS records are provided in this input."
            "Setting this field to true will remove the NS records in all cases, possibly resulting in an unusable "
            "zone."
        )
    ] = False


@dataclass
class GandiDNSError:
    cause: typing.Annotated[str, schema.name("Cause"), schema.description("What caused this error?")]
    code: typing.Annotated[int, schema.name("Code"), schema.description("Error code.")]
    message: typing.Annotated[str, schema.name("Message"), schema.description("Error message.")]
    object: typing.Annotated[str, schema.name("Object"), schema.description("Object this error refers to.")]


class AccessDeniedError(GandiDNSError):
    pass


class BadAuthenticationError(GandiDNSError):
    pass


@dataclass
class UnexpectedResponse:
    status_code: typing.Annotated[
        int,
        schema.name("HTTP status code"),
        schema.description("HTTP status code that was received."),
    ]
    body: typing.Annotated[
        str,
        schema.name("HTTP body"),
        schema.description("HTTP body that was received.")
    ]


@dataclass
class ConnectionFailed:
    message: typing.Annotated[str, schema.name("Message"), schema.description("Error message")]


@dataclass
class SetDNSZoneInput:
    api_key: typing.Annotated[
        str,
        schema.name("API key"),
        schema.description(
            "Gandi API key for updating live DNS. Request at https://account.gandi.net/en for production, or "
            "https://account.sandbox.gandi.net/en/users/arcabot/security for sandbox."
        ),
        schema.min(1)
    ]
    domain: typing.Annotated[
        str,
        schema.name("Domain name"),
        schema.description("Name of the domain to change."),
        schema.pattern(re.compile("^[a-zA-Z0-9-.]+$"))
    ]
    request: typing.Annotated[
        PutDomainRecordsRequest,
        schema.name("Domain configuration"),
        schema.description("Settings for the domain's DNS record"),
    ]
    endpoint: typing.Annotated[
        str,
        schema.name("API endpoint"),
        schema.description("API endpoint for managing Gandi resources. Defaults to the production API."),
        schema.example("https://api.gandi.net/v5/"),
        schema.example("https://api.sandbox.gandi.net/v5/"),
    ] = "https://api.gandi.net/v5/"


_request_schema = schema.build_object_schema(PutDomainRecordsRequest)
_response_schema = schema.build_object_schema(SetDNSZoneOutput)
_access_denied_schema = schema.build_object_schema(AccessDeniedError)
_bad_authentication_schema = schema.build_object_schema(BadAuthenticationError)


@plugin.step(
    id="gandi_set_dns_zone",
    name="Set DNS zone on Gandi",
    icon=_read_local_file("gandi.svg"),
    description="Completely replaces the DNS zone on Gandi live DNS.",
    outputs={
        "success": SetDNSZoneOutput,
        "access_denied": AccessDeniedError,
        "bad_authentication": BadAuthenticationError,
        "unexpected_response": UnexpectedResponse,
        "connection_failed": ConnectionFailed,
    }
)
def set_dns_zone(set_dns_zone_input: SetDNSZoneInput) -> typing.Tuple[
    str,
    typing.Union[SetDNSZoneOutput, AccessDeniedError, BadAuthenticationError, UnexpectedResponse, ConnectionFailed]
]:
    serialized_input = json.dumps(_request_schema.serialize(set_dns_zone_input.request))
    headers = {
        "Authorization": "Apikey " + set_dns_zone_input.api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-agent": "Gandi Arcaflow plugin"
    }
    try:
        resp = requests.put(
            set_dns_zone_input.endpoint + "/livedns/domains/" + set_dns_zone_input.domain + "/records",
            headers=headers,
            data=serialized_input
        )
    except Exception as e:
        return "connection_failed", ConnectionFailed(e.__str__())
    try:
        if resp.status_code == 200 or resp.status_code == 201:
            return "success", _response_schema.unserialize(resp.json())
        if resp.status_code == 403:
            return "access_denied", _access_denied_schema.unserialize(resp.json())
        if resp.status_code == 401:
            return "bad_authentication", _bad_authentication_schema.unserialize(resp.json())
    except JSONDecodeError:
        return "unexpected_response", UnexpectedResponse(resp.status_code, resp.text)
    except ConstraintException:
        return "unexpected_response", UnexpectedResponse(resp.status_code, resp.text)
    return "unexpected_response", UnexpectedResponse(resp.status_code, resp.text)


if __name__ == "__main__":
    sys.exit(plugin.run(plugin.build_schema(
        set_dns_zone,
    )))