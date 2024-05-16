import json
import logging
import re
import sys
from typing import Dict, List, Set

from json_flatten import flatten, unflatten


def set_excluded_fields(preset: str) -> Set[str]:
    excluded = []
    if preset == "cdxgen":
        excluded.extend(["metadata.timestamp", "serialNumber"])
    return set(excluded)


def check_key(key: str, exclude_keys: Set[str]) -> bool:
    return not any(key.startswith(k) for k in exclude_keys)


def compare_dicts(json1: str, json2: str, exclude_keys: Set[str], regex: bool):
    json_1_data = load_json(json1, exclude_keys, regex)
    json_2_data = load_json(json2, exclude_keys, regex)
    if json_1_data == json_2_data:
        return 0, json_1_data, json_2_data
    else:
        return 1, json_1_data, json_2_data


def get_diffs(file_1: str, file_2: str, json_1_data: Dict, json_2_data: Dict) -> Dict:
    j1 = {f"{key}:{value}" for key, value in json_1_data.items()}
    j2 = {f"{key}:{value}" for key, value in json_2_data.items()}
    result = unflatten({value.split(":")[0]: value.split(":")[1] for value in (j1 - j2)})
    result2 = unflatten({value.split(":")[0]: value.split(":")[1] for value in (j2 - j1)})
    return {file_1: result, file_2: result2}


def filter_dict(data: Dict, exclude_keys: Set[str], regex: bool) -> Dict:
    data = sort_dict(data)
    flattened = flatten(data)
    if regex:
        filtered = filter_regex(flattened, exclude_keys)
    else:
        filtered = filter_simple(flattened, exclude_keys)
    return filtered


def filter_simple(flattened_data: Dict, exclude_keys: Set[str]) -> Dict:
    return {
        key: value
        for key, value in flattened_data.items()
        if check_key(key, exclude_keys)
    }


def filter_regex(flattened_data: Dict, exclude_keys: Set[str]) -> Dict:
    exclude_keys = [re.compile(x) for x in exclude_keys]
    filtered = {}
    for key, value in flattened_data.items():
        for exclude_key in exclude_keys:
            if not re.match(exclude_key, key):
                filtered[key] = value
    return filtered


def get_sort_field(data: Dict) -> str:
    for i in ["url", "content", "ref", "name", "value"]:
        if i in data:
            return i
    raise ValueError("No sort field found")


def load_json(json_file: str, exclude_keys: Set[str], regex: bool) -> Dict:
    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        logging.error("File not found: %s", json_file)
        sys.exit(1)
    except json.JSONDecodeError:
        logging.error("Invalid JSON: %s", json_file)
        sys.exit(1)
    return filter_dict(data, exclude_keys, regex)


def remove_filepaths(data: Dict) -> Dict:
    # filtered_data = {}
    # for key, value in data.items():
    #     if isinstance(value, dict):
    #         filtered_data[key] = remove_filepaths(value)
    #     elif isinstance(value, list):
    #         filtered_data[key] = [item for item in value if not ]
    #     elif not (key == "value" and ("/" in value or r"\\" in value)):
    #         filtered_data[key] = value
    # return filtered_data
    raise NotImplementedError


def sort_dict(result: Dict) -> Dict:
    """Sorts a dictionary"""
    for k, v in result.items():
        if isinstance(v, dict):
            result[k] = sort_dict(v)
        elif isinstance(v, list) and len(v) >= 2:
            result[k] = sort_list(v)
        else:
            result[k] = v
    return result


def sort_list(lst: List) -> List:
    """Sorts a list"""
    if isinstance(lst[0], dict):
        sort_field = get_sort_field(lst[0])
        return sorted(lst, key=lambda x: x[sort_field])
    if isinstance(lst[0], (str, int)):
        lst.sort()
    return lst
