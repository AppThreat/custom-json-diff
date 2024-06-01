import json

import pytest

from custom_json_diff.custom_diff import compare_dicts, load_json, perform_bom_diff


@pytest.fixture
def java_1_bom():
    return load_json("test/sbom-java.json", False, "cdxgen", bom_diff=True)


@pytest.fixture
def java_2_bom():
    return load_json("test/sbom-java2.json", False, "cdxgen", bom_diff=True)


@pytest.fixture
def python_1_bom():
    return load_json("test/sbom-python.json", False, "cdxgen", bom_diff=True)


@pytest.fixture
def python_2_bom():
    return load_json("test/sbom-python2.json", False, "cdxgen", bom_diff=True)


@pytest.fixture
def results():
    with open("test/test_data.json", "r", encoding="utf-8") as f:
        return json.load(f)


def test_bom_diff(java_1_bom, java_2_bom, python_1_bom, python_2_bom, results):
    result, j1, j2 = compare_dicts(
        java_1_bom.filename, java_2_bom.filename, "cdxgen", True, False)
    result_summary = perform_bom_diff(j1, j2)
    assert result_summary == results["result_1"]
    result, p1, p2 = compare_dicts(python_1_bom.filename, python_2_bom.filename, "cdxgen", True, True)
    result_summary = perform_bom_diff(p1, p2)
    assert result_summary == results["result_2"]