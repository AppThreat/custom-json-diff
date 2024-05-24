import json
import logging
import re
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

import toml
from json_flatten import flatten, unflatten  # type: ignore


DELIM = "|>"


class FlatDicts:
    def __init__(self, elements):
        self.data, self.search_keys = import_flat_dict(elements)

    def __eq__(self, other):
        return all(i in other.data for i in self.data)

    def __ne__(self, other):
        return not self == other

    def __sub__(self, other):
        missing = [i for i in self.data if i not in other.data]
        return {i.key: i.value for i in missing}
        # new_flat_dict = {}
        # for i in missing:
        #     for j in self.data:
        #         if i == j.search_key:
        #             new_flat_dict[j.key] = j.value
        # return new_flat_dict

    def to_dict(self, unflat: bool = False):
        result = {i.key: i.value for i in self.data}
        if unflat:
            result = unflatten(result)
        return result

    def intersection(self, other):
        intersection = {}
        for i in self.data:
            if i.search_key in other.search_keys:
                intersection[i.key] = i.value
        return intersection

    def filter_out_keys(self, exclude_keys):
        filtered_data = []
        for i in self.data:
            if check_key(i.search_key, exclude_keys):
                filtered_data.append(i)
        self.data = filtered_data
        return self


class FlatElement:
    def __init__(self, key, value):
        self.key = key
        self.value = value
        self.search_key = create_search_key(key, value)

    def __eq__(self, other):
        return self.search_key == other.search_key


def check_key(key: str, exclude_keys: Set[str]) -> bool:
    return not any(key.startswith(k) for k in exclude_keys)


def check_regex(regex_keys: Set[re.Pattern], key: str) -> bool:
    return any(regex.match(key) for regex in regex_keys)


def compare_dicts(
        json1: str, json2: str, preset: str | None = None,
        excluded: List[str] | None = None, config: str | None = None
) -> Tuple[int, FlatDicts, FlatDicts]:
    if preset:
        exclude_keys, sort_keys = set_excluded_fields(preset)
    elif config:
        exclude_keys, sort_keys = import_toml(config)
    else:
        exclude_keys, sort_keys = set(excluded), []  # type: ignore
    json_1_data = load_json(json1, exclude_keys, sort_keys)
    json_2_data = load_json(json2, exclude_keys, sort_keys)
    if json_1_data.data == json_2_data.data:
        return 0, json_1_data, json_2_data
    else:
        return 1, json_1_data, json_2_data


def create_search_key(key: str, value: str) -> str:
    combined_key = re.sub(r"(?<=\[)[0-9]+(?=])", "", key)
    combined_key += f"|>{value}"
    return combined_key


def export_results(outfile: str, diffs: Dict) -> None:
    with open(outfile, "w", encoding="utf-8") as f:
        f.write(json.dumps(diffs, indent=2))


def filter_dict(data: Dict, exclude_keys: Set[str], sort_keys: List[str]) -> FlatDicts:
    data = flatten(sort_dict(data, sort_keys))
    return FlatDicts(data).filter_out_keys(exclude_keys)


def filter_simple(flattened_data: Dict, exclude_keys: Set[str]) -> Dict:
    return {
        key: value
        for key, value in flattened_data.items()
        if check_key(key, exclude_keys)
    }


def get_common(json_1_data: FlatDicts, json_2_data: FlatDicts) -> Dict:
    return unflatten(json_1_data.intersection(json_2_data))


def get_diffs(f1: str | Path, f2: str | Path, j1: FlatDicts, j2: FlatDicts) -> Dict:
    diff_1 = unflatten(j1 - j2)
    diff_2 = unflatten(j2 - j1)
    return {str(f1): diff_1, str(f2): diff_2}


def get_sort_key(data: Dict, sort_keys: List[str]) -> str | bool:
    return next((i for i in sort_keys if i in data), False)


def handle_results(outfile: str, diffs: Dict) -> None:
    if outfile:
        export_results(outfile, diffs)
    else:
        print("Differences found:")
        print(json.dumps(diffs, indent=2))


def import_flat_dict(my_dict: Dict) -> Tuple[List[FlatElement], Set[str]]:
    searchable = []
    search_keys = set()
    for key, value in my_dict.items():
        ele = FlatElement(key, value)
        searchable.append(ele)
        search_keys.add(ele.search_key)
    return searchable, search_keys


def import_toml(toml_file_path: str) -> Tuple[Set[str], List[str]]:
    with open(toml_file_path, "r", encoding="utf-8") as f:
        try:
            toml_data = toml.load(f)
        except toml.TomlDecodeError:
            logging.error("Invalid TOML.")
            sys.exit(1)
    try:
        return toml_data["settings"]["excluded_fields"], toml_data["settings"]["sort_keys"]
    except KeyError:
        logging.error("Invalid TOML.")
        sys.exit(1)


def load_json(json_file: str, exclude_keys: Set[str], sort_keys: List[str]) -> FlatDicts:
    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        logging.error("File not found: %s", json_file)
        sys.exit(1)
    except json.JSONDecodeError:
        logging.error("Invalid JSON: %s", json_file)
        sys.exit(1)
    return filter_dict(data, exclude_keys, sort_keys)


def perform_bom_diff(status: int, diff: Dict, commons: Dict, f1: str, f2: str, outfile: str):
    diff_elements = produce_bom_diff(diff, commons, f1, f2)
    handle_results(outfile, diff_elements)


def populate_bom_diff(diff: Dict) -> Dict:
    if not diff:
        return {"components": [], "services": []}
    return {
            "components": [i.get("purl") for i in diff.get("components", []) if i.get("purl")],
            "services": [i.get("bom-ref") for i in diff.get("services", []) if i.get("bom-ref")],
    }


def produce_bom_diff(diff: Dict, common: Dict, f1: str, f2: str) -> Dict:
    diff_summary = {f1: populate_bom_diff(diff.get(f1, {})), f2: populate_bom_diff(diff.get(f2, {}))}
    if common:
        diff_summary["common"] = populate_bom_diff(common)
    return diff_summary


def report_results(status: int, diffs: Dict, outfile: str):
    if status == 0:
        print("No differences found.")
    else:
        handle_results(outfile, diffs)


def set_excluded_fields(preset: str) -> Tuple[Set[str], List[str]]:
    excluded = []
    sort_fields = []
    if preset.startswith("cdxgen"):
        excluded.extend(["metadata.timestamp", "serialNumber",
                         "metadata.tools.components.[].version",
                         "metadata.tools.components.[].purl",
                         "metadata.tools.components.[].bom-ref",
                         "components.[].properties",
                         "components.[].evidence"
                         ])
        if preset == "cdxgen-extended":
            excluded.append("components.[].licenses")
        sort_fields.extend(["url", "content", "ref", "name", "value"])
    return set(excluded), sort_fields


def sort_dict(result: Dict, sort_keys: List[str]) -> Dict:
    """Sorts a dictionary"""
    for k, v in result.items():
        if isinstance(v, dict):
            result[k] = sort_dict(v, sort_keys)
        elif isinstance(v, list) and len(v) >= 2:
            result[k] = sort_list(v, sort_keys)
        else:
            result[k] = v
    return result


def sort_list(lst: List, sort_keys: List[str]) -> List:
    """Sorts a list"""
    if isinstance(lst[0], dict):
        if sort_key := get_sort_key(lst[0], sort_keys):
            return sorted(lst, key=lambda x: x[sort_key])
        logging.debug("No key(s) specified for sorting. Cannot sort list of dictionaries.")
        return lst
    if isinstance(lst[0], (str, int)):
        lst.sort()
    return lst
