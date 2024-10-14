import json

import pytest

from custom_json_diff.lib.custom_diff import (
    compare_dicts, get_bom_status, get_diff, json_to_class
)
from custom_json_diff.lib.custom_diff_classes import Options


@pytest.fixture
def java_1_flat():
    options = Options(file_1="test/sbom-java.json", file_2="test/sbom-java2.json", include=["licenses", "hashes"], exclude=["serialNumber", "metadata.timestamp"])
    return json_to_class("test/sbom-java.json", options)


@pytest.fixture
def java_2_flat():
    options = Options(file_1="test/sbom-java.json", file_2="test/sbom-java2.json", include=["licenses", "hashes"], exclude=["serialNumber", "metadata.timestamp"])
    return json_to_class("test/sbom-java2.json", options)


@pytest.fixture
def python_1_flat():
    options = Options(file_1="test/sbom-python.json", file_2="test/sbom-python2.json", include=["licenses", "hashes"], exclude=["serialNumber", "metadata.timestamp"])
    return json_to_class("test/sbom-python.json", options)


@pytest.fixture
def python_2_flat():
    options = Options(file_1="test/sbom-python.json", file_2="test/sbom-python2.json", include=["licenses", "hashes"], exclude=["serialNumber", "metadata.timestamp"])
    return json_to_class("test/sbom-python2.json", options)

@pytest.fixture
def python_3_flat():
    options = Options(file_1="test/sbom-python.json", file_2="test/sbom-python2.json", include=["licenses", "hashes"], exclude=["serialNumber", "metadata.timestamp"])
    return json_to_class("test/sbom-python2.json", options)


@pytest.fixture
def options_1():
    return Options(file_1="test/sbom-java.json", file_2="test/sbom-java2.json", include=["licenses", "hashes"], exclude=["serialNumber", "metadata.timestamp"])


@pytest.fixture
def options_2():
    return Options(file_1="test/sbom-python.json", file_2="test/sbom-python2.json", exclude=["serialNumber", "metadata.timestamp"])


@pytest.fixture
def results():
    with open("test/test_data.json", "r", encoding="utf-8") as f:
        return json.load(f)


def test_json_to_class(java_1_flat, java_2_flat):
    flattened = java_1_flat.to_dict()
    assert "serialNumber" not in flattened
    assert "metadata.timestamp" not in flattened
    assert "metadata.tools.components.[].version" not in java_2_flat.to_dict()


def test_compare_dicts(results, options_2):
    a, b, c = compare_dicts(options_2)
    assert a == 1
    diffs = get_diff(b, c, options_2)
    assert diffs == results["result_6"]
    commons = b.intersection(c).to_dict(True)
    assert commons == results["result_12"]


def test_flat_dicts_class(java_1_flat, python_1_flat, java_2_flat, python_2_flat, results):
    assert python_1_flat.intersection(python_2_flat).to_dict(True) == results["result_7"]
    assert (python_1_flat - python_2_flat).to_dict(True) == results["result_8"]
    assert ((python_2_flat - python_1_flat).to_dict(True)) == results["result_9"]
    assert (python_1_flat + python_2_flat).to_dict(True) == results["result_10"]
    python_1_flat -= python_2_flat
    assert python_1_flat.to_dict(True) == results["result_11"]


def test_get_bom_status():
    diff_summary_1 = {}
    diff_summary_2 = {}
    assert max(get_bom_status(diff_summary_1), get_bom_status(diff_summary_2)) == 0
    diff_summary_1 = {"components": {}}
    assert max(get_bom_status(diff_summary_1), get_bom_status(diff_summary_2)) == 0
    diff_summary_1 = {"components": {"applications": []}}
    assert max(get_bom_status(diff_summary_1), get_bom_status(diff_summary_2)) == 0
    diff_summary_1 = {"misc_data": {"key": "value"}}
    assert max(get_bom_status(diff_summary_1), get_bom_status(diff_summary_2)) == 2
    diff_summary_1["services"] = [{"name": "test"}]
    assert max(get_bom_status(diff_summary_1), get_bom_status(diff_summary_2)) == 3
