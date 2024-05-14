import argparse
import json
import logging
import re
import sys
from typing import Dict, List, Set

import json_flatten


def build_args():
    parser = argparse.ArgumentParser()
    arg_group = parser.add_mutually_exclusive_group()
    arg_group.add_argument(
        "-x",
        "--exclude",
        action="append",
        help="exclude field(s) from comparison",
        default=[],
        dest="exclude",
    )
    arg_group.add_argument(
        "-s",
        "--skip-filepaths",
        action="store_true",
        help="skip filepaths in comparison",
        default=False,
        dest="skip_filepaths",
        )
    arg_group.add_argument(
        "-p",
        "--preset",
        action="store",
        help="preset to use",
        choices=["cdxgen"],
        dest="preset",
    )
    parser.add_argument(
        "-i",
        "--input",
        action="store",
        help="input file",
        required=True,
        nargs=2,
        dest="input",
    )
    parser.add_argument(
        "-r",
        "--regex",
        action="store_true",
        help="Excluded keys are regular expressions.",
    )
    return parser.parse_args()


def check_key(key: str, exclude_keys: Set[str]) -> bool:
    return not any(key.startswith(k) for k in exclude_keys)


def compare_dicts(json1: str, json2: str, skip_filepaths: bool, exclude_keys: Set[str], regex: bool):
    json_1_data = sort_dict(load_json(json1, exclude_keys, regex, skip_filepaths))
    json_2_data = sort_dict(load_json(json2, exclude_keys, regex, skip_filepaths))
    return output_results(json_1_data, json_2_data)


def filter_dict(data: Dict, exclude_keys: Set[str], regex: bool, skip_filepaths: bool) -> Dict:
    flattened = json_flatten.flatten(data)
    if regex:
        filtered = filter_regex(flattened, exclude_keys)
    else:
        filtered = filter_simple(flattened, exclude_keys)
    if skip_filepaths:
        filtered = remove_filepaths(filtered)
    return json_flatten.unflatten(filtered)


def filter_simple(flattened_data: Dict, exclude_keys: Set[str]) -> Dict:
    filtered = {}
    for key, value in flattened_data.items():
        if check_key(key, exclude_keys):
            filtered[key] = value
    return filtered


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


def load_json(json_file: str, exclude_keys: Set[str], regex: bool, skip_filepaths: bool):
    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        logging.error("File not found: %s", json_file)
        sys.exit(1)
    except json.JSONDecodeError:
        logging.error("Invalid JSON: %s", json_file)
        sys.exit(1)
    return filter_dict(data, exclude_keys, regex, skip_filepaths)


def output_results(json_1_data: Dict, json_2_data: Dict):
    if json_1_data == json_2_data:
        return "JSON files are equal"
    else:
        return "JSON files are not equal"


def remove_filepaths(data: Dict) -> Dict:
    filtered_data = {}
    for key, value in data.items():
        if isinstance(value, dict):
            filtered_data[key] = remove_filepaths(value)
        elif not (key == "value" and ("/" in value or r"\\" in value)):
            filtered_data[key] = value
    return filtered_data


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
    if isinstance(lst[0], str) or isinstance(lst[0], int):
        lst.sort()
    return lst


def main():
    args = build_args()
    exclude_keys = set()
    if args.preset == "cdxgen":
        exclude_keys.add("serialNumber")
        exclude_keys.add("metadata.timestamp")
    else:
        exclude_keys = set(args.exclude)
    compare_dicts(args.input[0], args.input[1], args.skip_filepaths, exclude_keys, args.regex)


if __name__ == "__main__":
    main()
