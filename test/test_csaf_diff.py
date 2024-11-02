import json
from copy import deepcopy

import pytest

from custom_json_diff.lib.custom_diff import compare_dicts, perform_csaf_diff
from custom_json_diff.lib.custom_diff_classes import (CsafVulnerability, Options, BomVdr, BomVdrAffects
)
from custom_json_diff.lib.utils import filter_empty, json_dump


@pytest.fixture
def options_1():
    return Options(file_1="test/csaf_1.json", file_2="test/csaf_2.json", preconfig_type="csaf")


@pytest.fixture
def options_2():
    return Options(file_1="test/csaf_3.json", file_2="test/csaf_4.json", preconfig_type="csaf", exclude=["vulnerabilities.[].acknowledgements"])


@pytest.fixture
def options_3():
    return Options(file_1="test/csaf_1.json", file_2="test/csaf_2.json", preconfig_type="csaf", allow_new_data=True)


@pytest.fixture
def results():
    with open("test/test_data.json", "r", encoding="utf-8") as f:
        return json.load(f)


def test_csaf_diff(results, options_1, options_2):
    result, j1, j2 = compare_dicts(options_1)
    _, result_summary = perform_csaf_diff(j1, j2)
    results["result_13"] = result_summary
    assert result_summary == results["result_13"]

    result, j2, j1 = compare_dicts(options_1)
    _, result_summary = perform_csaf_diff(j2, j1)
    results["result_14"] = result_summary
    assert result_summary == results["result_14"]

    result, j1, j2 = compare_dicts(options_2)
    _, result_summary = perform_csaf_diff(j2, j1)
    assert filter_empty(False, result_summary["diff_summary"]) == {"test/csaf_3.json": {}, "test/csaf_4.json": {}}

    json_dump("test/results.json", results, compact=True)


def test_csaf_diff_vuln_options(options_1):
    # test don't allow --allow-new-data or --allow-new-versions
    csaf1 = CsafVulnerability({"cve": "CVE-2022-25881"},options=options_1)
    csaf2 = CsafVulnerability({"cve": "CVE-2022-25881"},options=options_1)
    csaf2.options.doc_num = 2
    assert csaf1 == csaf2
    csaf2.cve = "CVE-2022-25883"
    assert csaf1 != csaf2
    csaf1.clear(), csaf2.clear()

    csaf1.title, csaf2.title = "NPM-1091792/pkg:npm/base64url@0.0.6", "NPM-1091792/pkg:npm/base64url@0.0.6"
    assert csaf1 == csaf2
    csaf2.title = "NPM-1091792/pkg:npm/base64url@0.0.7"
    assert csaf1 != csaf2
    csaf1.clear(), csaf2.clear()

    csaf1.product_status = {
        "known_affected": [
          "org.apache.tomcat.embed/tomcat-embed-core@vers:maven/>=8.0.0|<8.5.61"
        ],
        "known_not_affected": [
          "org.apache.tomcat.embed/tomcat-embed-core@8.5.61"
        ]
      }
    csaf2.product_status = {
        "known_affected": [
          "org.apache.tomcat.embed/tomcat-embed-core@vers:maven/>=8.0.0|<8.5.61"
        ],
        "known_not_affected": [
          "org.apache.tomcat.embed/tomcat-embed-core@8.5.61"
        ]
      }
    assert csaf1 == csaf2
    csaf2.product_status = {
        "known_affected": [
          "org.apache.tomcat.embed/tomcat-embed-core@vers:maven/>=8.0.0|<8.5.61"
        ]
      }
    assert csaf1 != csaf2
    csaf1.clear(), csaf2.clear()

    csaf1.cwe = {"id": "502", "name": "Deserialization of Untrusted Data"}
    csaf2.cwe = {"id": "502", "name": "Deserialization of Untrusted Data"}
    assert csaf1 == csaf2
    csaf2.cwe = {"id": "502"}
    assert csaf1 != csaf2
    csaf1.clear(), csaf2.clear()

    csaf1.notes = [
        {
          "category": "description",
          "details": "Vulnerability Description",
          "text": "Deserialization of Untrusted Data in logback"
        },
        {
          "category": "details",
          "details": "Vulnerability Details",
          "text": "# Deserialization of Untrusted Data in logback In logback version 1.2.7 and prior versions, an attacker with the required privileges to edit configurations files could craft a malicious configuration allowing to execute arbitrary code loaded from LDAP servers."
        }
      ]
    csaf2.notes = [{"category": "details", "details": "Vulnerability Details",
        "text": "# Deserialization of Untrusted Data in logback In logback version 1.2.7 and prior versions, an attacker with the required privileges to edit configurations files could craft a malicious configuration allowing to execute arbitrary code loaded from LDAP servers."},
        {
          "category": "description",
          "details": "Vulnerability Description",
          "text": "Deserialization of Untrusted Data in logback"
        }
      ]
    assert csaf1 == csaf2
    csaf2.notes.pop()
    assert csaf1 != csaf2
    csaf1.clear(), csaf2.clear()

    csaf1.discovery_date, csaf2.discovery_date = "2020-09-01T20:42:44", "2020-09-01T20:42:44"
    assert csaf1 == csaf2
    csaf2.discovery_date = "2021-09-01T20:42:44"
    assert csaf1 != csaf2
    csaf1.clear(), csaf2.clear()

    csaf1.scores = [{
          "cvss_v3": {
            "attackComplexity": "HIGH",
            "attackVector": "NETWORK",
            "availabilityImpact": "HIGH",
            "baseScore": 6.6,
            "baseSeverity": "MEDIUM",
            "confidentialityImpact": "HIGH",
            "environmentalScore": 6.6,
            "environmentalSeverity": "MEDIUM",
            "integrityImpact": "HIGH",
            "modifiedAttackComplexity": "HIGH",
            "modifiedAttackVector": "NETWORK",
            "modifiedAvailabilityImpact": "HIGH",
            "modifiedConfidentialityImpact": "HIGH",
            "modifiedIntegrityImpact": "HIGH",
            "modifiedPrivilegesRequired": "HIGH",
            "modifiedScope": "UNCHANGED",
            "modifiedUserInteraction": "NONE",
            "privilegesRequired": "HIGH",
            "scope": "UNCHANGED",
            "temporalScore": 6.6,
            "temporalSeverity": "MEDIUM",
            "userInteraction": "NONE",
            "vectorString": "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H",
            "version": "3.1"
          },
          "products": [
            "ch.qos.logback/logback-core@vers:maven/>=0.2.5|<=1.2.8"
          ]
        }]
    csaf2.scores = [{
          "cvss_v3": {
            "attackComplexity": "HIGH",
            "attackVector": "NETWORK",
            "availabilityImpact": "HIGH",
            "baseScore": 6.6,
            "baseSeverity": "MEDIUM",
            "confidentialityImpact": "HIGH",
            "environmentalScore": 6.6,
            "environmentalSeverity": "MEDIUM",
            "integrityImpact": "HIGH",
            "modifiedAttackComplexity": "HIGH",
            "modifiedAttackVector": "NETWORK",
            "modifiedAvailabilityImpact": "HIGH",
            "modifiedConfidentialityImpact": "HIGH",
            "modifiedIntegrityImpact": "HIGH",
            "modifiedPrivilegesRequired": "HIGH",
            "modifiedScope": "UNCHANGED",
            "modifiedUserInteraction": "NONE",
            "privilegesRequired": "HIGH",
            "scope": "UNCHANGED",
            "temporalScore": 6.6,
            "temporalSeverity": "MEDIUM",
            "userInteraction": "NONE",
            "vectorString": "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H",
            "version": "3.1"
          },
          "products": [
            "ch.qos.logback/logback-core@vers:maven/>=0.2.5|<=1.2.8"
          ]
        }]
    assert csaf1 == csaf2
    csaf2.scores = [{
          "cvss_v3": {
            "attackComplexity": "HIGH",
            "attackVector": "NETWORK",
            "availabilityImpact": "HIGH",
            "baseScore": 6.7,
            "baseSeverity": "MEDIUM",
            "confidentialityImpact": "HIGH",
            "environmentalScore": 6.6,
            "environmentalSeverity": "MEDIUM",
            "integrityImpact": "HIGH",
            "modifiedAttackComplexity": "HIGH",
            "modifiedAttackVector": "NETWORK",
            "modifiedAvailabilityImpact": "HIGH",
            "modifiedConfidentialityImpact": "HIGH",
            "modifiedIntegrityImpact": "HIGH",
            "modifiedPrivilegesRequired": "HIGH",
            "modifiedScope": "UNCHANGED",
            "modifiedUserInteraction": "NONE",
            "privilegesRequired": "HIGH",
            "scope": "UNCHANGED",
            "temporalScore": 6.6,
            "temporalSeverity": "MEDIUM",
            "userInteraction": "NONE",
            "vectorString": "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H",
            "version": "3.1"
          },
          "products": [
            "ch.qos.logback/logback-core@vers:maven/>=0.2.5|<=1.2.8"
          ]
        }]
    assert csaf1 != csaf2
    csaf1.clear(), csaf2.clear()

    csaf1.references = [{"summary": "CVE-2022-23541", "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-23541"}]
    csaf2.references = [{"summary": "CVE-2022-23541", "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-23541"}]
    assert csaf1 == csaf2
    csaf1.references.append({
        "summary": "GHSA-hjrf-2m68-5959", "url": "https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-hjrf-2m68-5959"})
    assert csaf1 != csaf2
    csaf1.clear(), csaf2.clear()

    csaf1.acknowledgements = [{"urls": ["https://nvd.nist.gov/vuln/detail/CVE-2022-23541"], "organization": "NVD"}]
    csaf2.acknowledgements = [{"urls": ["https://nvd.nist.gov/vuln/detail/CVE-2022-23541"], "organization": "NVD"}]
    assert csaf1 == csaf2
    csaf2.acknowledgements = [{"urls": ["https://nvd.nist.gov/vuln/detail/CVE-2022-23542"], "organization": "NVD"}]
    assert csaf1 != csaf2
    csaf1.clear(), csaf2.clear()


def test_csaf_diff_vuln_options_allow_new_data(options_3):
    # test --allow-new-data
    options_3_copy = deepcopy(options_3)
    options_3_copy.doc_num = 2
    csaf1, csaf2 = CsafVulnerability(data={},options=options_3), CsafVulnerability(data={},options=options_3_copy)

    csaf1.acknowledgements = []
    csaf2.acknowledgements = [{"organization": "NVD", "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2024-39689"]}]
    assert csaf1 == csaf2
    csaf1.acknowledgements, csaf2.acknowledgements = csaf2.acknowledgements, csaf1.acknowledgements
    assert csaf1 != csaf2
    csaf1.clear(), csaf2.clear()

    csaf1.references = [{"summary": "CVE-2022-23541", "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-23541"}]
    csaf2.references = [{"summary": "CVE-2022-23541", "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-23541"}]
    assert csaf1 == csaf2
    csaf1.references.append({
        "summary": "GHSA-hjrf-2m68-5959", "url": "https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-hjrf-2m68-5959"})
    assert csaf1 != csaf2
    csaf1.clear(), csaf2.clear()
