import json
import logging
import re
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

import toml
from json_flatten import flatten, unflatten


DELIM = "|>"


def check_key(key: str, exclude_keys: Set[str]) -> bool:
    return not any(key.startswith(k) for k in exclude_keys)


def check_regex(regex_keys: List[re.Pattern], key: str) -> bool:
    return any(regex.match(key) for regex in regex_keys)


def compare_dicts(
        json1: str | Path, json2: str | Path, preset: str | None = None,
        excluded: List[str] | None = None, config: str | None = None
) -> Tuple[int, Dict[str, str], Dict[str, str]]:
    if preset:
        exclude_keys, sort_keys = set_excluded_fields(preset)
    elif config:
        exclude_keys, sort_keys = import_toml(config)
    else:
        exclude_keys, sort_keys = set(excluded), []
    json_1_data = load_json(json1, exclude_keys, sort_keys)
    json_2_data = load_json(json2, exclude_keys, sort_keys)
    if json_1_data == json_2_data:
        return 0, json_1_data, json_2_data
    else:
        return 1, json_1_data, json_2_data


def export_results(outfile, diffs):
    with open(outfile, "w", encoding="utf-8") as f:
        f.write(json.dumps(diffs, indent=2))


def filter_advanced(flattened_data: Dict, exclude_keys: Set[str]) -> Dict:
    mod_data = {}
    for key, value in flattened_data.items():
        new_key = key.replace("[", "#").replace("]", "%")
        mod_data[new_key] = value
    exclude_keys = [re.compile(x.replace("[]", "#[0-9]+%")) for x in exclude_keys]
    return {
        key.replace("#", "[").replace("%", "]"): value
        for key, value in mod_data.items()
        if not check_regex(exclude_keys, key)
    }


def filter_dict(data: Dict, exclude_keys: Set[str], sort_keys: List[str]) -> Dict:
    data = sort_dict(data, sort_keys)
    flattened = flatten(data)
    has_arrays = any("[" in i for i in exclude_keys)
    return (
        filter_advanced(flattened, exclude_keys)
        if has_arrays
        else filter_simple(flattened, exclude_keys)
    )


def filter_simple(flattened_data: Dict, exclude_keys: Set[str]) -> Dict:
    return {
        key: value
        for key, value in flattened_data.items()
        if check_key(key, exclude_keys)
    }


def get_diffs(file_1: str | Path, file_2: str | Path, json_1_data: Dict, json_2_data: Dict) -> Dict:
    j1 = {f"{key}{DELIM}{value}" for key, value in json_1_data.items()}
    j2 = {f"{key}{DELIM}{value}" for key, value in json_2_data.items()}
    result = unflatten({value.split(DELIM)[0]: value.split(DELIM)[1] for value in (j1 - j2)})
    result2 = unflatten({value.split(DELIM)[0]: value.split(DELIM)[1] for value in (j2 - j1)})
    return {str(file_1): result, str(file_2): result2}


def get_sort_key(data: Dict, sort_keys: List[str]) -> str | bool:
    return next((i for i in sort_keys if i in data), False)


def import_toml(toml_file_path):
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


def load_json(json_file: str, exclude_keys: Set[str], sort_keys: List[str]) -> Dict:
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


def sort_dict(result: Dict, sort_keys: List[str], unflat: bool = False) -> Dict:
    """Sorts a dictionary"""
    for k, v in result.items():
        if isinstance(v, dict):
            result[k] = sort_dict(v, sort_keys)
        elif isinstance(v, list) and len(v) >= 2:
            result[k] = sort_list(v, sort_keys)
        else:
            result[k] = v
    if unflat:
        result = unflatten(result)
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

