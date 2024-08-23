import json
from copy import deepcopy

import pytest

from custom_json_diff.lib.custom_diff import compare_dicts, perform_bom_diff
from custom_json_diff.lib.custom_diff_classes import (
    BomComponent, BomDicts, FlatDicts, Options, BomVdr, BomVdrAffects
)


@pytest.fixture
def options_1():
    return Options(file_1="test/sbom-java.json", file_2="test/sbom-java2.json", bom_diff=True, include=["hashes", "evidence", "licenses"])


@pytest.fixture
def options_2():
    return Options(file_1="test/sbom-python.json", file_2="test/sbom-python2.json", bom_diff=True, allow_new_versions=True, include=["hashes", "evidence", "properties"])


@pytest.fixture
def options_3():
    return Options(file_1="bom_1.json", file_2="bom_2.json", bom_diff=True, allow_new_data=True)


@pytest.fixture
def options_4():
    return Options(file_1="bom_1.json", file_2="bom_2.json", bom_diff=True, allow_new_versions=True, allow_new_data=True, include=["hashes", "evidence", "properties"])


@pytest.fixture
def bom_dicts_1():
    options = Options(file_1="bom_1.json", file_2="bom_2.json",
                      bom_diff=True, allow_new_data=True)
    bom_dicts = BomDicts(options, "bom_1.json", {}, FlatDicts({}), [])
    bom_dicts.components = [BomComponent({
        "bom-ref": "pkg:maven/org.springframework.cloud/spring-cloud-starter-config@2.0.0"
                   ".RELEASE?type=jar",
        "description": "", "group": "org.springframework.cloud",
        "name": "spring-cloud-starter-config", "publisher": "Pivotal Software, Inc.",
        "purl": "pkg:maven/org.springframework.cloud/spring-cloud-starter-config@2.0.0.RELEASE"
                "?type=jar",
        "scope": "required", "type": "framework", "version": "2.0.0.RELEASE"}, options),
        BomComponent({"bom-ref": "pkg:maven/joda-time/joda-time@2.9.9?type=jar",
                      "description": "Date and time library to replace JDK date handling",
                      "group": "joda-time", "name": "joda-time", "publisher": "Joda.org",
                      "purl": "pkg:maven/joda-time/joda-time@2.9.9?type=jar", "scope": "required",
                      "type": "library", "version": "2.9.9"}, options)]
    return bom_dicts


@pytest.fixture
def bom_dicts_2():
    options = Options(file_1="bom_1.json", file_2="bom_2.json",
                      bom_diff=True, allow_new_data=True)
    bom_dicts = BomDicts(options, "bom_2.json", {}, FlatDicts({}), [])
    bom_dicts.components = [BomComponent({
        "bom-ref": "pkg:maven/org.springframework.cloud/spring-cloud-starter-config@2.0.0"
                   ".RELEASE?type=jar",
        "description": "Spring Cloud Starter", "group": "org.springframework.cloud",
        "name": "spring-cloud-starter-config", "publisher": "Pivotal Software, Inc.",
        "purl": "pkg:maven/org.springframework.cloud/spring-cloud-starter-config@2.0.0.RELEASE"
                "?type=jar",
        "scope": "required", "type": "framework", "version": "2.0.0.RELEASE"}, options),
        BomComponent({"bom-ref": "pkg:maven/joda-time/joda-time@2.9.9?type=jar",
                      "description": "",
                      "group": "joda-time", "name": "joda-time", "publisher": "Joda.org",
                      "purl": "pkg:maven/joda-time/joda-time@2.9.9?type=jar", "scope": "required",
                      "type": "library", "version": "2.9.9"}, options)]
    return bom_dicts


@pytest.fixture
def bom_dicts_3():
    options = Options(file_1="bom_1.json", file_2="bom_2.json", bom_diff=True, allow_new_versions=True, comp_only=True)
    bom_dicts = BomDicts(options, "bom_1.json", {}, FlatDicts({}), [])
    bom_dicts.components = [BomComponent({
        "bom-ref": "pkg:maven/org.springframework.cloud/spring-cloud-starter-config@2.0.0"
                   ".RELEASE?type=jar",
        "description": "Spring Cloud Starter", "group": "org.springframework.cloud",
        "name": "spring-cloud-starter-config", "publisher": "Pivotal Software, Inc.",
        "purl": "pkg:maven/org.springframework.cloud/spring-cloud-starter-config@2.0.0.RELEASE"
                "?type=jar",
        "scope": "required", "type": "framework", "version": "2.0.0.RELEASE"}, options),
        BomComponent({"bom-ref": "pkg:maven/joda-time/joda-time@2.9.9?type=jar",
                      "description": "Date and time library to replace JDK date handling",
                      "group": "joda-time", "name": "joda-time", "publisher": "Joda.org",
                      "purl": "pkg:maven/joda-time/joda-time@2.9.9?type=jar", "scope": "required",
                      "type": "library", "version": "2.9.9"}, options)]
    return bom_dicts


@pytest.fixture
def bom_dicts_4():
    options = Options(file_1="bom_1.json", file_2="bom_2.json", bom_diff=True, allow_new_versions=True, comp_only=True)
    bom_dicts = BomDicts(options, "bom_2.json", {}, FlatDicts([]))
    bom_dicts.components = [BomComponent({
        "bom-ref": "pkg:maven/org.springframework.cloud/spring-cloud-starter-config@2.3.0"
                   ".RELEASE?type=jar",
        "description": "Spring Cloud Starter", "group": "org.springframework.cloud",
        "name": "spring-cloud-starter-config", "publisher": "Pivotal Software, Inc.",
        "purl": "pkg:maven/org.springframework.cloud/spring-cloud-starter-config@2.3.0.RELEASE"
                "?type=jar",
        "scope": "required", "type": "framework", "version": "2.3.0.RELEASE"}, options),
        BomComponent({"bom-ref": "pkg:maven/joda-time/joda-time@2.8.9?type=jar",
                      "description": "Date and time library to replace JDK date handling",
                      "group": "joda-time", "name": "joda-time", "publisher": "Joda.org",
                      "purl": "pkg:maven/joda-time/joda-time@2.8.9?type=jar", "scope": "required",
                      "type": "library", "version": "2.8.9"}, options)]
    return bom_dicts


@pytest.fixture
def bom_dicts_5():
    options = Options(file_1="bom_1.json", file_2="bom_2.json", bom_diff=True, allow_new_versions=True, allow_new_data=True)
    bom_dicts = BomDicts(options, "bom_1.json", {}, {})
    bom_dicts.components = [BomComponent(
        {"bom-ref": "pkg:pypi/flask@1.1.2", "group": "", "name": "flask",
            "purl": "pkg:pypi/flask@1.1.2", "type": "framework", "version": "1.1.2"}, options),
        BomComponent({"bom-ref": "pkg:pypi/werkzeug@1.0.1", "group": "", "name": "Werkzeug",
            "purl": "pkg:pypi/werkzeug@1.0.1", "type": "library", "version": "1.0.1"}, options),
        BomComponent({"bom-ref": "pkg:github/actions/checkout@v2", "group": "", "name": "checkout",
            "purl": "pkg:github/actions/checkout@v2", "type": "application", "version": "v2"},
            options), BomComponent(
            {"bom-ref": "pkg:github/actions/setup-python@v2", "group": "actions",
                "name": "setup-python", "purl": "pkg:github/actions/setup-python@v2",
                "type": "application", "version": "v2"}, options)]
    return bom_dicts


@pytest.fixture
def bom_dicts_6():
    options = Options(file_1="bom_1.json", file_2="bom_2.json", bom_diff=True, allow_new_versions=True, allow_new_data=True)
    bom_dicts = BomDicts(options, "bom_2.json", {}, {})
    bom_dicts.components = [
        BomComponent({
      "bom-ref": "pkg:pypi/flask@1.1.0",
      "group": "",
      "name": "flask",
      "purl": "pkg:pypi/flask@1.1.0",
      "type": "framework",
      "version": "1.1.0"
    }, options),
        BomComponent({
      "bom-ref": "pkg:pypi/werkzeug@1.1.1",
      "group": "",
      "name": "Werkzeug",
      "purl": "pkg:pypi/werkzeug@1.1.1",
      "type": "library",
      "version": "1.1.1"
    }, options),
        BomComponent({
      "bom-ref": "pkg:github/actions/checkout@v2",
      "group": "actions",
      "name": "checkout",
      "purl": "pkg:github/actions/checkout@v2",
      "type": "application",
      "version": "v2"
    }, options),
        BomComponent({
      "bom-ref": "pkg:github/actions/setup-python@v2",
      "group": "",
      "name": "setup-python",
      "purl": "pkg:github/actions/setup-python@v2",
      "type": "application",
      "version": "v2"
    }, options)
    ]
    return bom_dicts


@pytest.fixture
def bom_dicts_7():
    options = Options(file_1="bom_1.json", file_2="bom_2.json", bom_diff=True, allow_new_data=True,
                      allow_new_versions=True)
    bom_dicts = BomDicts(options, "bom_1.json", {}, {}, components=[BomComponent(
        {"bom-ref": "pkg:pypi/requests@2.31.0", "evidence": {
            "identity": {"confidence": 0.8, "field": "purl", "methods": [
                {"confidence": 0.8, "technique": "manifest-analysis",
                    "value": "/home/runner/work/src_repos/python/django-goat/requirements_tests.txt"}]}},
            "group": "", "name": "requests", "properties": [{"name": "SrcFile",
            "value": "/home/runner/work/src_repos/python/django-goat/requirements_tests.txt"}],
            "purl": "pkg:pypi/requests@2.31.0", "type": "library", "version": "2.31.0"},
        options), ])
    return bom_dicts


@pytest.fixture
def bom_dicts_8():
    options = Options(file_1="bom_1.json", file_2="bom_2.json", bom_diff=True, allow_new_data=True,
                      allow_new_versions=True)
    bom_dicts = BomDicts(options, "bom_2.json", {}, {}, components=[
    BomComponent({
      "bom-ref": "pkg:pypi/requests@2.32.3",
      "evidence": {
        "identity": {
          "confidence": 0.8,
          "field": "purl",
          "methods": [
            {
              "confidence": 0.8,
              "technique": "manifest-analysis",
              "value": "/home/runner/work/src_repos/python/django-goat/requirements_tests.txt"
            }
          ]
        }
      },
      "group": "",
      "name": "requests",
      "properties": [
        {
          "name": "SrcFile",
          "value": "/home/runner/work/src_repos/python/django-goat/requirements_tests.txt"
        }
      ],
      "purl": "pkg:pypi/requests@2.32.3",
      "type": "library",
      "version": "2.32.3"
    }, options)], )

    return bom_dicts


@pytest.fixture
def bom_component_1():
    return BomComponent(
        {
          "bom-ref": "pkg:maven/io.netty/netty-resolver-dns@4.1.110.Final-SNAPSHOT?type=jar",
          "group": "io.netty",
          "name": "netty-resolver-dns",
          "properties": [
            {
              "name": "SrcFile",
              "value": "/home/runner/work/src_repos/java/netty/pom.xml"
            },
            {
              "name": "SrcFile",
              "value": "/home/runner/work/src_repos/java/netty/resolver-dns-native-macos/pom.xml"
            },
            {
              "name": "SrcFile",
              "value": "/home/runner/work/src_repos/java/netty/resolver-dns-classes-macos/pom.xml"
            },
          ],
          "publisher": "The Netty Project",
          "purl": "pkg:maven/io.netty/netty-resolver-dns@4.1.110.Final-SNAPSHOT?type=jar",
          "scope": "required",
          "type": "framework",
          "version": "4.1.110.Final-SNAPSHOT"
        }, Options(file_1="bom_1.json", file_2="bom_2.json", bom_diff=True, allow_new_data=True, bom_num=1)
    )


@pytest.fixture
def bom_component_2():
    return BomComponent(
        {
          "bom-ref": "pkg:maven/io.netty/netty-resolver-dns@4.1.110.Final-SNAPSHOT?type=jar",
          "group": "io.netty",
          "name": "netty-resolver-dns",
          "properties": [
            {
              "name": "SrcFile",
              "value": "/home/runner/work/src_repos/java/netty/pom.xml"
            },
            {
              "name": "SrcFile",
              "value": "/home/runner/work/src_repos/java/netty/resolver-dns-native-macos/pom.xml"
            },
            {
              "name": "SrcFile",
              "value": "/home/runner/work/src_repos/java/netty/resolver-dns-classes-macos/pom.xml"
            },
            {
              "name": "SrcFile",
              "value": "/home/runner/work/src_repos/java/netty/handler-ssl-ocsp/pom.xml"
            },
            {
              "name": "SrcFile",
              "value": "/home/runner/work/src_repos/java/netty/all/pom.xml"
            }
          ],
          "publisher": "The Netty Project",
          "purl": "pkg:maven/io.netty/netty-resolver-dns@4.1.110.Final-SNAPSHOT?type=jar",
          "scope": "required",
          "type": "framework",
          "version": "4.1.110.Final-SNAPSHOT"
        }, Options(file_1="bom_1.json", file_2="bom_2.json", bom_diff=True, allow_new_data=True, bom_num=2)
    )


@pytest.fixture
def results():
    with open("test/test_data.json", "r", encoding="utf-8") as f:
        return json.load(f)


def test_bom_diff(results, options_1):
    result, j1, j2 = compare_dicts(options_1)
    _, result_summary = perform_bom_diff(j1, j2)
    assert result_summary == results["result_4"]


def test_bom_diff_component_options(results, bom_dicts_1, bom_dicts_2, bom_dicts_3, bom_dicts_4, bom_dicts_5, bom_dicts_6, bom_dicts_7, bom_dicts_8):
    # test --allow-new-data for components
    _, result_summary = perform_bom_diff(bom_dicts_1, bom_dicts_2)
    assert result_summary == results["result_1"]

    # test --allow-new-versions for components
    _, result_summary = perform_bom_diff(bom_dicts_3, bom_dicts_4)
    assert result_summary == results["result_2"]

    # test --allow-new-data and --allow-new-versions for components
    _, result_summary = perform_bom_diff(bom_dicts_5, bom_dicts_6)
    assert result_summary == results["result_3"]

    _, result_summary = perform_bom_diff(bom_dicts_7, bom_dicts_8)
    assert result_summary == results["result_5"]


def test_bom_diff_vdr_options(options_1):
    # test don't allow --allow-new-data or --allow-new-versions
    bom1 = BomVdr(id="CVE-2022-25881",options=options_1)
    bom2 = BomVdr(id="CVE-2022-25881",options=options_1)
    bom2.options.bom_num = 2
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


def test_bom_diff_vdr_options_allow_new_versions(options_2):
    # test --allow-new-versions
    options_2.bom_num = 1
    options_2_copy = deepcopy(options_2)
    options_2_copy.bom_num = 2
    bom1, bom2 = BomVdr(options=options_2), BomVdr(options=options_2_copy)

    bom1.bom_ref, bom2.bom_ref = "NPM-1091792/pkg:npm/base64url@0.0.6", "NPM-1091792/pkg:npm/base64url@0.0.7"
    assert bom1 == bom2
    bom1.bom_ref, bom2.bom_ref = bom2.bom_ref, bom1.bom_ref
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.affects = [BomVdrAffects(data={"ref": "pkg:npm/libxmljs2@0.33.0", "versions": [{
        "range": "vers:npm/>=0.0.0|<=1.0.11", "status": "affected"}]}, options=bom1.options)]
    bom2.affects = [BomVdrAffects(data={"ref": "pkg:npm/libxmljs2@0.33.1", "versions": [{
        "range": "vers:npm/>=0.0.0|<=1.0.11", "status": "affected"}]}, options=bom2.options)]
    assert bom1 == bom2
    bom1.affects = [BomVdrAffects(data={"ref": "pkg:npm/libxmljs2@0.33.1", "versions": [{
        "range": "vers:npm/>=0.0.0|<=1.0.11", "status": "affected"}]}, options=bom1.options)]
    bom2.affects = [BomVdrAffects(data={"ref": "pkg:npm/libxmljs2@0.33.0", "versions": [{
        "range": "vers:npm/>=0.0.0|<=1.0.11", "status": "affected"}]}, options=bom2.options)]
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.updated, bom2.updated = "2020-09-01T20:42:44", "2021-09-01T20:42:44"
    assert bom1 == bom2
    bom1.updated, bom2.updated = bom2.updated, bom1.updated
    assert bom1 != bom2


def test_bom_diff_vdr_options_allow_new_data(options_3):
    # test --allow-new-data
    options_3_copy = deepcopy(options_3)
    options_3_copy.bom_num = 2
    bom1, bom2 = BomVdr(id="",options=options_3), BomVdr(id="CVE-2022-25881",options=options_3_copy)
    assert bom1 == bom2
    bom1.id, bom2.id = "CVE-2022-25883", ""
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.bom_ref, bom2.bom_ref = "", "NPM-1091792/pkg:npm/base64url@0.0.6"
    assert bom1 == bom2
    bom1.bom_ref, bom2.bom_ref = bom2.bom_ref, bom1.bom_ref
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.advisories = []
    bom2.advisories = [{"url": "https://security.netapp.com/advisory/ntap-20230622-0008"}]
    assert bom1 == bom2
    bom1.advisories, bom2.advisories= bom2.advisories, bom1.advisories
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.affects = []
    bom2.affects = [BomVdrAffects(data={"ref": "pkg:npm/libxmljs2@0.33.0", "versions": [{"range": "vers:npm/>=0.0.0|<=1.0.11", "status": "affected"}]}, options=bom2.options)]
    assert bom1 == bom2
    bom1.affects, bom2.affects = bom2.affects, bom1.affects
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.analysis = {}
    bom2.analysis = {"state": "exploitable", "detail": "See https://seclists.org/bugtraq/2019/May/68"}
    assert bom1 == bom2
    bom1.analysis, bom2.analysis = bom2.analysis, bom1.analysis
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.cwes = ["1333"]
    bom2.cwes = ["1333", "1334"]
    assert bom1 == bom2
    bom1.cwes, bom2.cwes = bom2.cwes, bom1.cwes
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.description, bom2.description = "", "lorem ipsum dolor sit amet"
    assert bom1 == bom2
    bom1.description, bom2.description = bom2.description, bom1.description
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.detail, bom2.detail = "", "lorem ipsum dolor sit amet"
    assert bom1 == bom2
    bom1.detail, bom2.detail = bom2.detail, bom1.detail
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.properties = []
    bom2.properties = [{"name": "depscan:insights", "value": "Indirect dependency"}]
    assert bom1 == bom2
    bom1.properties, bom2.properties = bom2.properties, bom1.properties
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.published, bom2.published = "", "2020-09-01T20:42:44"
    assert bom1 == bom2
    bom1.published, bom2.published = bom2.published, bom1.published
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.ratings = []
    bom2.ratings = [{"method": "CVSSv31", "severity": "MEDIUM", "score": 5.0,
                     "vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L"}]
    assert bom1 == bom2
    bom1.ratings, bom2.ratings = bom2.ratings, bom1.ratings
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.recommendation, bom2.recommendation = "", "lorem ipsum dolor sit amet"
    assert bom1 == bom2
    bom1.recommendation, bom2.recommendation = bom2.recommendation, bom1.recommendation
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.references = []
    bom2.references = [{"id": "CVE-2022-23541", "source": {"url": "https://nvd.nist.gov/vuln/detail/CVE-2022-23541", "name": "NVD"}}]
    assert bom1 == bom2
    bom1.references, bom2.references = bom2.references, bom1.references
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.source = {}
    bom2.source = {"url": "https://nvd.nist.gov/vuln/detail/CVE-2022-23541", "name": "NVD"}
    assert bom1 == bom2
    bom1.source, bom2.source = bom2.source, bom1.source
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.updated, bom2.updated = "", "2021-09-01T20:42:44"
    assert bom1 == bom2
    bom1.updated, bom2.updated = bom2.updated, bom1.updated
    assert bom1 != bom2


def test_bom_diff_vdr_options_allow_all(options_4):
    # test --allow-new-data
    options_4_copy = deepcopy(options_4)
    options_4_copy.bom_num = 2
    bom1, bom2 = BomVdr(id="",options=options_4), BomVdr(id="CVE-2022-25881",options=options_4_copy)
    assert bom1 == bom2
    bom1.id, bom2.id = "CVE-2022-25883", ""
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.affects = [BomVdrAffects(data={"ref": "pkg:npm/libxmljs2@0.33.0", "versions": [{"range": "vers:npm/>=0.0.0|<=1.0.11", "status": "affected"}]}, options=bom1.options)]
    bom2.affects = [
        BomVdrAffects(data={"ref": "pkg:npm/libxmljs2@0.33.0", "versions": [{"range": "vers:npm/>=0.0.0|<=1.0.11", "status": "affected"}]}, options=bom2.options),
        BomVdrAffects(data={"ref": "pkg:npm/libxmljs2@0.33.1", "versions": [{"range": "vers:npm/>=0.0.0|<=1.0.11", "status": "affected"}]}, options=bom2.options)
    ]
    assert bom1 == bom2
    bom1.affects, bom2.affects = bom2.affects, bom1.affects
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.analysis = {}
    bom2.analysis = {"state": "exploitable", "detail": "See https://seclists.org/bugtraq/2019/May/68"}
    assert bom1 == bom2
    bom1.analysis, bom2.analysis = bom2.analysis, bom1.analysis
    assert bom1 != bom2
    bom1.clear(), bom2.clear()

    bom1.updated, bom2.updated = "", "2021-09-01T20:42:44"
    assert bom1 == bom2
    bom1.updated, bom2.updated = bom2.updated, bom1.updated
    assert bom1 != bom2
    bom1.updated, bom2.updated = "2020-09-01T20:42:44", "2021-09-01T20:42:44"
    assert bom1 == bom2


def test_bom_components_lists(bom_component_1, bom_component_2):
    # tests allow_new_data with component lists of dicts
    assert bom_component_1 == bom_component_2
    bom_component_1.options.bom_num = 2
    bom_component_2.options.bom_num = 1
    assert bom_component_1 != bom_component_2
