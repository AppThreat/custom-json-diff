import json

import pytest

from custom_json_diff.custom_diff import (
    compare_dicts, get_diff, load_json, sort_dict
)


@pytest.fixture
def java_1_flat():
    return load_json("test/sbom-java.json", False, "cdxgen")


@pytest.fixture
def java_2_flat():
    return load_json("test/sbom-java2.json", False, "cdxgen")


@pytest.fixture
def python_1_flat():
    return load_json("test/sbom-python.json", False, "cdxgen")


@pytest.fixture
def python_2_flat():
    return load_json("test/sbom-python2.json", False, "cdxgen")


@pytest.fixture
def results():
    with open("test/test_data.json", "r", encoding="utf-8") as f:
        return json.load(f)


def test_load_json(java_1_flat, java_2_flat):
    java_1_flat = java_1_flat.to_dict()
    assert "serialNumber" not in java_1_flat
    assert "metadata.timestamp" not in java_1_flat
    assert "metadata.tools.components.[].version" not in java_2_flat.to_dict()


def test_sort_dict(java_1_flat, python_1_flat, java_2_flat, results):
    x = {"a": 1, "b": 2, "c": [3, 2, 1], "d": [{"name": "test 3", "value": 1}, {"name": "test 2", "value": 2}]}
    assert sort_dict(x, ["url", "content", "ref", "name", "value"]) == {"a": 1, "b": 2, "c": [1, 2, 3], "d": [{"name": "test 2", "value": 2}, {"name": "test 3", "value": 1}]}
    assert sort_dict(java_2_flat.to_dict(True), ["url", "content", "ref", "name", "value"]) == results["result_3"]
    assert sort_dict(python_1_flat.to_dict(True), ["url", "content", "ref", "name", "value"]) == results["result_4"]

def test_compare_dicts(results):
    a, b, c = compare_dicts("test/sbom-python.json", "test/sbom-python2.json", "cdxgen", False, False)
    assert a == 1
    diffs = get_diff("test/sbom-python.json", "test/sbom-python2.json", b, c)
    assert diffs == results["result_5"]
    commons = b.intersection(c).to_dict(True)
    assert commons == results["result_6"]


def test_flat_dicts_class(java_1_flat, python_1_flat, java_2_flat, python_2_flat, results):
    assert python_1_flat.intersection(python_2_flat).to_dict(True) == results["result_7"]
    assert (python_1_flat - python_2_flat).to_dict(True) == results["result_8"]
    assert ((python_2_flat - python_1_flat).to_dict(True)) == results["result_9"]
    assert (python_1_flat + python_2_flat).to_dict(True) == results["result_10"]
    python_1_flat -= python_2_flat
    assert python_1_flat.to_dict(True) == results["result_11"]