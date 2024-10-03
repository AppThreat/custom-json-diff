import json
from copy import deepcopy

import pytest

from custom_json_diff.lib.custom_diff import compare_dicts, perform_csaf_diff
from custom_json_diff.lib.custom_diff_classes import (CsafDicts, CsafVulnerability, Options, BomVdr, BomVdrAffects
)


@pytest.fixture
def options_1():
    return Options(file_1="test/csaf_1.json", file_2="test/csaf_2.json", preconfig_type="csaf")


@pytest.fixture
def options_3():
    return Options(file_1="test/csaf_1.json", file_2="test/csaf_2.json", preconfig_type="csaf", allow_new_data=True)


@pytest.fixture
def csaf_dicts_1():
    options = Options(file_1="csaf_1.json", file_2="csaf_2.json", preconfig_type="csaf", allow_new_data=True)
    return CsafDicts(options, "csaf_1.json", vulnerabilities=[CsafVulnerability({
      "acknowledgements": [
        [
          {
            "organization": "NVD",
            "urls": [
              "https://nvd.nist.gov/vuln/detail/CVE-2024-39689"
            ]
          }
        ]
      ],
      "cve": "CVE-2024-39689",
      "cwe": {
        "id": "345",
        "name": "Insufficient Verification of Data Authenticity"
      },
      "discovery_date": "2024-07-05T20:06:40",
      "ids": [
        {
          "system_name": "CVE Record",
          "text": "CVE-2024-39689"
        },
        {
          "system_name": "GitHub Advisory",
          "text": "GHSA-248v-346w-9cwc"
        }
      ],
      "notes": [
        {
          "category": "description",
          "details": "Vulnerability Description",
          "text": "Certifi removes GLOBALTRUST root certificate"
        },
        {
          "category": "details",
          "details": "Vulnerability Details",
          "text": "# Certifi removes GLOBALTRUST root certificate Certifi 2024.07.04 removes root certificates from \"GLOBALTRUST\" from the root store. These are in the process of being removed from Mozilla's trust store.  GLOBALTRUST's root certificates are being removed pursuant to an investigation which identified \"long-running and unresolved compliance issues\". Conclusions of Mozilla's investigation can be found [here]( https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/XpknYMPO8dI)."
        }
      ],
      "product_status": {
        "known_affected": [
          "certifi@vers:pypi/>=2021.05.30|<2024.07.04"
        ],
        "known_not_affected": [
          "certifi@2024.07.04"
        ]
      },
      "references": [
        {
          "summary": "GitHub Advisory GHSA-248v-346w-9cwc",
          "url": "https://github.com/certifi/python-certifi/security/advisories/GHSA-248v-346w-9cwc"
        },
        {
          "summary": "Google Mailing List",
          "url": "https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/XpknYMPO8dI"
        },
        {
          "summary": "CVE Record",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-39689"
        }
      ],
      "scores": [
        {
          "cvss_v3": {
            "attackComplexity": "HIGH",
            "attackVector": "NETWORK",
            "availabilityImpact": "NONE",
            "baseScore": 3.1,
            "baseSeverity": "LOW",
            "confidentialityImpact": "LOW",
            "environmentalScore": 3.1,
            "environmentalSeverity": "LOW",
            "integrityImpact": "NONE",
            "modifiedAttackComplexity": "HIGH",
            "modifiedAttackVector": "NETWORK",
            "modifiedAvailabilityImpact": "NONE",
            "modifiedConfidentialityImpact": "LOW",
            "modifiedIntegrityImpact": "NONE",
            "modifiedPrivilegesRequired": "NONE",
            "modifiedScope": "UNCHANGED",
            "modifiedUserInteraction": "REQUIRED",
            "privilegesRequired": "NONE",
            "scope": "UNCHANGED",
            "temporalScore": 3.1,
            "temporalSeverity": "LOW",
            "userInteraction": "REQUIRED",
            "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
            "version": "3.1"
          },
          "products": [
            "certifi@vers:pypi/>=2021.05.30|<2024.07.04"
          ]
        }
      ],
      "title": "CVE-2024-39689/pkg:pypi/certifi@2023.7.22"
    }, options)

    ])


@pytest.fixture
def results():
    with open("test/test_data.json", "r", encoding="utf-8") as f:
        return json.load(f)


def test_csaf_diff(results, options_1):
    result, j1, j2 = compare_dicts(options_1)
    _, result_summary = perform_csaf_diff(j1, j2)
    assert result_summary == results["result_13"]
    result, j2, j1 = compare_dicts(options_1)
    _, result_summary = perform_csaf_diff(j2, j1)
    results["result_14"] = result_summary
    assert result_summary == results["result_14"]


def test_csaf_diff_vuln_options(options_1):
    # test don't allow --allow-new-data or --allow-new-versions
    bom1 = BomVdr(id="CVE-2022-25881",options=options_1)
    bom2 = BomVdr(id="CVE-2022-25881",options=options_1)
    bom2.options.doc_num = 2
    assert bom1 == bom2
    bom2.id = "CVE-2022-25883"
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.bom_ref, bom2.bom_ref = "NPM-1091792/pkg:npm/base64url@0.0.6", "NPM-1091792/pkg:npm/base64url@0.0.6"
    assert bom1 == bom2
    bom2.bom_ref = "NPM-1091792/pkg:npm/base64url@0.0.7"
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.advisories = [{"url": "https://security.netapp.com/advisory/ntap-20230622-0008"}]
    bom2.advisories = [{"url": "https://security.netapp.com/advisory/ntap-20230622-0008"}]
    assert bom1 == bom2
    bom2.advisories = [{"url": "https://security.netapp.com/advisory/ntap-20230622-0009"}]
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.affects = [BomVdrAffects({"ref": "pkg:npm/libxmljs2@0.33.0", "versions": [{
        "range": "vers:npm/>=0.0.0|<=1.0.11", "status": "affected"}]}, options=bom1.options)]
    bom2.affects = [BomVdrAffects(data={"ref": "pkg:npm/libxmljs2@0.33.0", "versions": [{
        "range": "vers:npm/>=0.0.0|<=1.0.11", "status": "affected"}]}, options=bom2.options)]
    assert bom1 == bom2
    bom2.affects = [BomVdrAffects(data={"ref": "pkg:npm/libxmljs2@0.33.1", "versions": [{
        "range": "vers:npm/>=0.0.0|<=1.0.11", "status": "affected"}]}, options=bom2.options)]
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.analysis = {"state": "exploitable", "detail": "See https://seclists.org/bugtraq/2019/May/68"}
    bom2.analysis = {"state": "exploitable", "detail": "See https://seclists.org/bugtraq/2019/May/68"}
    assert bom1 == bom2
    bom1.analysis = {}
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.cwes = ["1333"]
    bom2.cwes = ["1333"]
    assert bom1 == bom2
    bom2.cwes = ["1333", "1334"]
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.description = "lorem ipsum dolor sit amet"
    bom2.description = "lorem ipsum dolor sit amet"
    assert bom1 == bom2
    bom2.description = "lorem ipsum dolor"
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.detail = "lorem ipsum dolor sit amet"
    bom2.detail = "lorem ipsum dolor sit amet"
    assert bom1 == bom2
    bom2.detail = "lorem ipsum dolor"
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.properties = [{"name": "depscan:insights", "value": "Indirect dependency"}]
    bom2.properties = [{"name": "depscan:insights", "value": "Indirect dependency"}]
    assert bom1 == bom2
    bom2.properties = [{"name": "depscan:insights", "value": "Indirect dependency"}, {"name": "depscan:prioritized", "value": "false"}]
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.published, bom2.published = "2020-09-01T20:42:44", "2020-09-01T20:42:44"
    assert bom1 == bom2
    bom2.published = "2021-09-01T20:42:44"
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.ratings = [{"method": "CVSSv31", "severity": "MEDIUM", "score": 5.0, "vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L"}]
    bom2.ratings = [{"method": "CVSSv31", "severity": "MEDIUM", "score": 5.0, "vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L"}]
    assert bom1 == bom2
    bom2.ratings = [{"method": "CVSSv31", "severity": "MEDIUM", "score": 7.0, "vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L"}]
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.recommendation, bom2.recommendation = "lorem ipsum dolor sit amet", "lorem ipsum dolor sit amet"
    assert bom1 == bom2
    bom2.recommendation = "lorem ipsum dolor"
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.references = [{"id": "CVE-2022-23541", "source": {"url": "https://nvd.nist.gov/vuln/detail/CVE-2022-23541", "name": "NVD"}}]
    bom2.references = [{"id": "CVE-2022-23541", "source": {"url": "https://nvd.nist.gov/vuln/detail/CVE-2022-23541", "name": "NVD"}}]
    assert bom1 == bom2
    bom1.references.append({"id": "GHSA-hjrf-2m68-5959", "source": {"name": "GitHub Advisory", "url": "https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-hjrf-2m68-5959"}})
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.source = {"url": "https://nvd.nist.gov/vuln/detail/CVE-2022-23541", "name": "NVD"}
    bom2.source = {"url": "https://nvd.nist.gov/vuln/detail/CVE-2022-23541", "name": "NVD"}
    assert bom1 == bom2
    bom2.source = {"url": "https://nvd.nist.gov/vuln/detail/CVE-2022-23542", "name": "NVD"}
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.updated, bom2.updated = "2020-09-01T20:42:44", "2020-09-01T20:42:44"
    assert bom1 == bom2
    bom2.updated = "2021-09-01T20:42:44"
    assert bom1 != bom2


def test_csaf_diff_vuln_options_allow_new_data(options_3):
    # test --allow-new-data
    options_3_copy = deepcopy(options_3)
    options_3_copy.doc_num = 2
    csaf1, csaf2 = CsafVulnerability(data={"title": "CVE-2022-25881"},options=options_3), CsafVulnerability(data={"title": "CVE-2022-25881"},options=options_3_copy)
    assert csaf1 == csaf2
    csaf1.title, csaf2.title = "CVE-2022-25883", ""
    assert csaf1 != csaf2
    csaf1.clear(), csaf2.clear()

    csaf1.acknowledgements = []
    csaf2.acknowledgements = [{"organization": "NVD", "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2024-39689"]}]
    assert csaf1 == csaf2
    csaf1.acknowledgements, csaf2.acknowledgements = csaf2.acknowledgements, csaf1.acknowledgements
    assert csaf1 != csaf2
    csaf1.clear(), csaf2.clear()

    csaf1.cwe = {"id": "345", "name": "Insufficient Verification of Data Authenticity"}
    csaf2.cwe = {"id": "345", "name": "Insufficient Verification of Data Authenticity"}
    assert csaf1 == csaf2
    csaf1.cwe["id"] = "500"
    assert csaf1 != csaf2
    csaf1.clear(), csaf2.clear()

    csaf1.discovery_date, csaf2.discovery_date = "", "2020-09-01T20:42:44"
    assert csaf1 == csaf2
    csaf1.discovery_date, csaf2.discovery_date = csaf2.discovery_date, csaf1.discovery_date
    assert csaf1 != csaf2
    csaf1.clear(), csaf2.clear()
