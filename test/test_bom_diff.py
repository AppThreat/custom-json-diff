import json

import pytest

from custom_json_diff.custom_diff import compare_dicts, load_json, perform_bom_diff
from custom_json_diff.custom_diff_classes import Options


@pytest.fixture
def java_1_bom():
    options = Options(file_1="test/sbom-java.json", file_2="test/sbom-java2.json", bom_diff=True)
    return load_json("test/sbom-java.json", options)


@pytest.fixture
def java_2_bom():
    options = Options(file_1="test/sbom-java.json", file_2="test/sbom-java2.json", bom_diff=True)
    return load_json("test/sbom-java2.json", options)


@pytest.fixture
def python_1_bom():
    options = Options(file_1="test/sbom-python.json", file_2="test/sbom-python2.json", bom_diff=True)
    return load_json("test/sbom-python.json", options)


@pytest.fixture
def python_2_bom():
    options = Options(file_1="test/sbom-python.json", file_2="test/sbom-python2.json", bom_diff=True)
    return load_json("test/sbom-python2.json", options)


@pytest.fixture
def options_1():
    return Options(file_1="test/sbom-java.json", file_2="test/sbom-java2.json", bom_diff=True)


@pytest.fixture
def options_2():
    return Options(file_1="test/sbom-python.json", file_2="test/sbom-python2.json", bom_diff=True, allow_new_versions=True)


@pytest.fixture
def results():
    with open("test/test_data.json", "r", encoding="utf-8") as f:
        return json.load(f)


def test_bom_diff(java_1_bom, java_2_bom, python_1_bom, python_2_bom, results, options_1, options_2):
    result, j1, j2 = compare_dicts(options_1)
    result_summary = perform_bom_diff(j1, j2, options_1)
    assert result_summary == results["result_1"]
    result, p1, p2 = compare_dicts(options_2)
    result_summary = perform_bom_diff(p1, p2, options_2)
    assert result_summary == results["result_2"]