import json

import pytest

from custom_json_diff.custom_diff import compare_dicts, load_json, perform_bom_diff
from custom_json_diff.custom_diff_classes import BomComponent, BomDicts, Options


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
def bom_dicts_1():
    options = Options(file_1="bom_1.json", file_2="bom_2.json",
                      bom_diff=True, allow_new_data=True)
    bom_dicts = BomDicts(options, "bom_1.json", {}, {})
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
    bom_dicts = BomDicts(options, "bom_2.json", {}, {})
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
    bom_dicts = BomDicts(options, "bom_1.json", {}, {})
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
    bom_dicts = BomDicts(options, "bom_2.json", {}, {})
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
    options = Options(file_1="bom_1.json", file_2="bom_2.json",
                      bom_diff=True, allow_new_data=True, allow_new_versions=True)
    bom_dicts = BomDicts(options, "bom_1.json", {}, {})
    bom_dicts.components = [
    BomComponent({
      "bom-ref": "pkg:pypi/requests@2.31.0",
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
      "purl": "pkg:pypi/requests@2.31.0",
      "type": "library",
      "version": "2.31.0"
    }, options),
]
    return bom_dicts


@pytest.fixture
def bom_dicts_8():
    options = Options(file_1="bom_1.json", file_2="bom_2.json",
                      bom_diff=True, allow_new_data=True, allow_new_versions=True)
    bom_dicts = BomDicts(options, "bom_2.json", {}, {})
    bom_dicts.components = [
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
    }, options),
]
    return bom_dicts


@pytest.fixture
def bom_component_9():
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
def bom_component_10():
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
    result_summary = perform_bom_diff(j1, j2)
    assert result_summary == results["result_4"]


def test_bom_diff_options(results, bom_dicts_1, bom_dicts_2, bom_dicts_3, bom_dicts_4, bom_dicts_5, bom_dicts_6, bom_dicts_7, bom_dicts_8):
    # test --allow-new-data
    result_summary = perform_bom_diff(bom_dicts_1, bom_dicts_2)
    assert result_summary == results["result_1"]

    # test --allow-new-versions
    result_summary = perform_bom_diff(bom_dicts_3, bom_dicts_4)
    assert result_summary == results["result_2"]

    # test --allow-new-data and --allow-new-versions
    result_summary = perform_bom_diff(bom_dicts_7, bom_dicts_8)
    assert result_summary == results["result_5"]

    result_summary = perform_bom_diff(bom_dicts_5, bom_dicts_6)
    assert result_summary == results["result_3"]


def test_bom_components_lists(bom_component_9, bom_component_10):
    # tests allow_new_data with component lists of dicts
    assert bom_component_9 == bom_component_10
    bom_component_9.options.bom_num = 2
    bom_component_10.options.bom_num = 1
    assert bom_component_9 != bom_component_10
