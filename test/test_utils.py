import os.path
from datetime import datetime

import semver

from custom_json_diff.lib.utils import (
    compare_bom_refs,
    compare_date,
    compare_generic,
    compare_recommendations,
    compare_versions,
    filter_empty,
    import_config,
    json_dump,
    json_load,
    manual_version_compare,
    sort_dict,
    split_bom_ref
)


def test_compare_bom_refs():
    assert compare_bom_refs("", "pkg:pypi/werkzeug@1.0.1", "=") is False
    assert compare_bom_refs("pkg:maven/org.springframework.cloud/spring-cloud-starter@2.0.0.RELEASE", "pkg:maven/org.springframework.cloud/spring-cloud-starter@2.0.0.RELEASE?type=jar", "=") is True
    assert compare_bom_refs("pkg:pypi/werkzeug@1.1.1", "pkg:pypi/werkzeug@1.0.1", "<=") is False
    assert compare_bom_refs("pkg:pypi/werkzeug@1.0.1", "pkg:pypi/werkzeug@1.1.1", "<=") is True
    assert compare_bom_refs("pkg:pypi/werkzeug@1.0", "pkg:pypi/werkzeug@1.1", "<=") is True
    assert compare_bom_refs("", "", "=") is True
    assert compare_bom_refs("", "", "<") is False


def test_compare_date():
    assert compare_date("", "", "=") is True
    assert compare_date("", "", "==") is True
    assert compare_date("", "", "<") is False
    assert compare_date("2024-06-05T03:01:41.936Z", "2024-06-05", ">=") is True
    assert compare_date("2024-06-05T03:01:41.936Z", "2024-06-06", "<=") is True
    assert compare_date("2024-06-05T03:01:41.936Z", "2024-06-06", ">") is False
    assert compare_date("", "2024-06-05", ">=") is False
    assert compare_date("55-55-55", "2024-06-05", ">=") is True


def test_compare_generic():
    assert compare_generic("", "", "=") is True
    assert compare_generic("", "", "==") is True
    assert compare_generic("", "", "<") is False
    assert compare_generic("1.0", "0.9", ">=") is True
    assert compare_generic(semver.Version.parse("1.0.0"), semver.Version.parse("0.9.0"), ">=") is True


def test_compare_recommendations():
    assert compare_recommendations("Update to 3.1.", "Update to 3.2.", "<=") is True
    assert compare_recommendations("Update to 3.9.", "Update to version 3.13.", "<=") is True
    assert compare_recommendations("Update to 3.9.", "Update to v3.13.", "<=") is True
    assert compare_recommendations("", "Update to version 3.13.", "<=") is True


def test_compare_versions():
    assert compare_versions("", "", "=") is True
    assert compare_versions("", "", "==") is True
    assert compare_versions("", "", "<") is False
    assert compare_versions("", "0.9.0", "=") is False
    assert compare_versions("1.0.0", "0.9.0", ">=") is True


def test_filter_empty():
    assert filter_empty(True, {"a": 1, "b": None}) == {"a": 1, "b": None}
    assert filter_empty(False, {"a": 1, "b": None}) == {"a": 1}
    assert filter_empty(False, {"a": 1, "b": {"c": 1, "d": []}}) == {"a": 1, "b": {"c": 1}}


def test_import_config():
    assert import_config("test/config.toml") == {
        'preset_settings': {'allow_new_data': False, 'allow_new_versions': True,
                            'components_only': False,
                            'include_extra': ['licenses', 'properties', 'hashes', 'evidence'],
                            'report_template': 'custom_json_diff/bom_diff_template.j2',
                            'type': 'bom'}, 'settings': {'excluded_fields': [],
                                                         'sort_keys': ['url', 'content', 'ref',
                                                                       'name', 'value']}}


def test_json_dump():
    json_dump("testfile.json", {"a": {1, 2, 3}}, sort_keys=["a"])
    assert not os.path.exists("testfile.json")


def test_json_load():
    assert list(json_load("test/test_data.json").keys()) == ['result_1', 'result_10', 'result_11',
                                                             'result_12', 'result_13', 'result_14',
                                                             'result_2', 'result_3', 'result_4',
                                                             'result_5', 'result_6', 'result_7',
                                                             'result_8', 'result_9']
    assert json_load("notafile.json") == {}


def test_manual_version_compare():
    assert manual_version_compare("1.0.0", "0.9.0", ">=") is True
    assert manual_version_compare("1.0.0", "1.0.1", ">=") is False
    assert manual_version_compare("2024-10", "2024-09", ">=") is True
    assert manual_version_compare("1.0.0", "0.9.0", "<=") is False
    assert manual_version_compare("1.0.0", "1.0.1", "<=") is True
    assert manual_version_compare("2024-10", "2024-09", "<=") is False
    assert manual_version_compare("1.0.0", "0.9.0", ">") is True
    assert manual_version_compare("1.0.0", "1.0.1", ">") is False
    assert manual_version_compare("2024-10", "2024-09", ">") is True
    assert manual_version_compare("1.0.0", "0.9.0", ">=") is True
    assert manual_version_compare(".", ".", ".") is True


def test_sort_dict():
    x = {
        "a": 1, "b": 2, "c": [3, 2, 1],
        "d": [{"name": "test 3", "value": 1}, {"value": 3}, {"name": "test 2", "value": 2}]
    }

    assert sort_dict(x, ["url", "content", "ref", "name", "value"]) == {
        "a": 1, "b": 2, "c": [1, 2, 3],
        "d": [{"name": "test 3", "value": 1}, {"name": "test 2", "value": 2}, {"value": 3}]
    }


def test_split_bom_ref():
    assert split_bom_ref("pkg:pypi/werkzeug@1.1.1") == ("pkg:pypi/werkzeug", "1.1.1")
    assert split_bom_ref("pkg:pypi/werkzeug@v1.1.1?type=jar") == ("pkg:pypi/werkzeug", "1.1.1")
    assert split_bom_ref("pkg:pypi/werkzeug") == ("pkg:pypi/werkzeug", "")
