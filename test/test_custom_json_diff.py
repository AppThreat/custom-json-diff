import json

import pytest

from custom_json_diff.custom_diff import (
    compare_dicts, get_diff, load_json, sort_dict_lists
)
from custom_json_diff.custom_diff_classes import Options


@pytest.fixture
def java_1_flat():
    options = Options(file_1="test/sbom-java.json", file_2="test/sbom-java2.json", testing=True, include=["licenses", "hashes"])
    return load_json("test/sbom-java.json", options)


@pytest.fixture
def java_2_flat():
    options = Options(file_1="test/sbom-java.json", file_2="test/sbom-java2.json", testing=True, include=["licenses", "hashes"])
    return load_json("test/sbom-java2.json", options)


@pytest.fixture
def python_1_flat():
    options = Options(file_1="test/sbom-python.json", file_2="test/sbom-python2.json", testing=True, include=["licenses", "hashes"])
    return load_json("test/sbom-python.json", options)


@pytest.fixture
def python_2_flat():
    options = Options(file_1="test/sbom-python.json", file_2="test/sbom-python2.json", testing=True, include=["licenses", "hashes"])
    return load_json("test/sbom-python2.json", options)


@pytest.fixture
def options_1():
    return Options(file_1="test/sbom-java.json", file_2="test/sbom-java2.json", testing=True, include=["licenses", "hashes"])


@pytest.fixture
def options_2():
    return Options(file_1="test/sbom-python.json", file_2="test/sbom-python2.json", testing=True)


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
    assert sort_dict_lists(x, ["url", "content", "ref", "name", "value"]) == {"a": 1, "b": 2, "c": [1, 2, 3], "d": [{"name": "test 2", "value": 2}, {"name": "test 3", "value": 1}]}


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
