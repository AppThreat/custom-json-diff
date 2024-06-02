import json
import logging
import os
import re
import sys
from typing import Dict, List, Set, Tuple

from jinja2 import Environment
from json_flatten import flatten, unflatten  # type: ignore

from custom_json_diff.custom_diff_classes import BomDicts, FlatDicts, Options


def check_regex(regex_keys: Set[re.Pattern], key: str) -> bool:
    return any(regex.match(key) for regex in regex_keys)


def compare_dicts(options: Options) -> Tuple[int, FlatDicts | BomDicts, FlatDicts | BomDicts]:
    json_1_data = load_json(options.file_1, options)
    json_2_data = load_json(options.file_2, options)
    if json_1_data == json_2_data:
        return 0, json_1_data, json_2_data
    else:
        return 1, json_1_data, json_2_data


def export_html_report(outfile: str, diffs: Dict, options: Options) -> None:
    if options.report_template:
        template_file = options.report_template
    else:
        template_file = options.report_template or os.path.join(
                    os.path.dirname(os.path.realpath(__file__)), "bom_diff_template.j2")
    with open(template_file, "r", encoding="utf-8") as tmpl_file:
        template = tmpl_file.read()
    jinja_env = Environment(autoescape=False)
    jinja_tmpl = jinja_env.from_string(template)
    purl_regex = re.compile(r"[^/]+@[^?\s]+")
    diffs["diff_summary"][options.file_1]["dependencies"] = parse_purls(
        diffs["diff_summary"][options.file_1]["dependencies"], purl_regex)
    diffs["diff_summary"][options.file_2]["dependencies"] = parse_purls(
        diffs["diff_summary"][options.file_2]["dependencies"], purl_regex)
    diffs["commons_summary"]["dependencies"] = parse_purls(
        diffs["commons_summary"]["dependencies"], purl_regex)
    report_result = jinja_tmpl.render(
        common_lib=diffs.get("commons_summary", {}).get("components", {}).get("libraries", []),
        common_frameworks=diffs.get("commons_summary", {}).get("components", {}).get("frameworks", []),
        common_services=diffs.get("commons_summary", {}).get("services", []),
        common_deps=diffs.get("commons_summary", {}).get("dependencies", []),
        diff_lib_1=diffs.get("diff_summary", {}).get(options.file_1, {}).get("components", {}).get("libraries", []),
        diff_lib_2=diffs.get("diff_summary", {}).get(options.file_2, {}).get("components", {}).get("libraries", []),
        diff_frameworks_1=diffs.get("diff_summary", {}).get(options.file_1, {}).get("components", {}).get("frameworks", []),
        diff_frameworks_2=diffs.get("diff_summary", {}).get(options.file_2, {}).get("components", {}).get("frameworks", []),
        diff_services_1=diffs.get("diff_summary", {}).get(options.file_1, {}).get("services", []),
        diff_services_2=diffs.get("diff_summary", {}).get(options.file_2, {}).get("services", []),
        diff_deps_1=diffs.get("diff_summary", {}).get(options.file_1, {}).get("dependencies", []),
        diff_deps_2=diffs.get("diff_summary", {}).get(options.file_2, {}).get("dependencies", []),
        bom_1=options.file_1,
        bom_2=options.file_2
    )
    with open(outfile, "w", encoding="utf-8") as f:
        f.write(report_result)
    print(f"HTML report generated: {outfile}")


def parse_purls(deps: List[Dict], regex: re.Pattern) -> List[Dict]:
    if not deps:
        return deps
    for i in deps:
        i["short_ref"] = match[0] if (match := regex.findall(i["ref"])) else i["ref"]
    return deps


def export_results(outfile: str, diffs: Dict) -> None:
    with open(outfile, "w", encoding="utf-8") as f:
        f.write(json.dumps(diffs, indent=2))
    print(f"JSON report generated: {outfile}")


def filter_dict(data: Dict, options: Options) -> FlatDicts:
    data = flatten(sort_dict(data, options.sort_keys))
    return FlatDicts(data).filter_out_keys(options.exclude)


def get_bom_commons(bom_1: BomDicts, bom_2: BomDicts) -> Dict:
    commons = {"metadata": (bom_1.data.intersection(bom_2.data)).to_dict(True)}
    libraries = [i.original_data for i in bom_1.components if i in bom_2.components and i.component_type == "library"]
    frameworks = [i.original_data for i in bom_1.components if i in bom_2.components and i.component_type == "framework"]
    commons["components"] = {"libraries": libraries, "frameworks": frameworks}
    commons["services"] = [i.original_data for i in bom_1.services if i in bom_2.services]  # type: ignore
    commons["dependencies"] = [i.original_data for i in bom_1.dependencies if i in bom_2.dependencies]  # type: ignore
    return commons


def get_bom_diff(bom_1: BomDicts, bom_2: BomDicts, options: Options) -> Dict:
    diff = get_diff(bom_1.data, bom_2.data, options)
    diff[bom_1.filename] |= populate_bom_diff(bom_1, bom_2)
    diff[bom_2.filename] |= populate_bom_diff(bom_2, bom_1)
    return diff


def get_diff(j1: FlatDicts, j2: FlatDicts, options: Options) -> Dict:
    diff_1 = (j1 - j2).to_dict(unflat=True)
    diff_2 = (j2 - j1).to_dict(unflat=True)
    return {options.file_1: diff_1, options.file_2: diff_2}


def get_sort_key(data: Dict, sort_keys: List[str]) -> str | bool:
    return next((i for i in sort_keys if i in data), False)


def handle_results(outfile: str, diffs: Dict) -> None:
    if outfile:
        export_results(outfile, diffs)
    if not outfile:
        print(json.dumps(diffs, indent=2))


def load_json(json_file: str, options: Options) -> FlatDicts | BomDicts:
    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        logging.error("File not found: %s", json_file)
        sys.exit(1)
    except json.JSONDecodeError:
        logging.error("Invalid JSON: %s", json_file)
        sys.exit(1)
    if options.bom_diff:
        data = sort_dict(data, ["url", "content", "ref", "name", "value"])
        return BomDicts(options.allow_new_versions, json_file, data)
    return filter_dict(data, options)


def perform_bom_diff(bom_1: BomDicts, bom_2: BomDicts, options: Options) -> Dict:
    return {
        "commons_summary": get_bom_commons(bom_1, bom_2),
        "diff_summary": get_bom_diff(bom_1, bom_2, options)
    }


def populate_bom_diff(bom_1: BomDicts, bom_2: BomDicts) -> Dict:
    diff: Dict = {}
    diff |= {
        "components": {
            "libraries": [
                i.original_data
                for i in bom_1.components
                if i not in bom_2.components and i.component_type == "library"],
            "frameworks": [
                i.original_data for i in bom_1.components if
                i not in bom_2.components and i.component_type == "framework"
            ]
        }
    }
    diff |= {"services": [i.original_data for i in bom_1.services if i not in bom_2.services]}
    diff |= {"dependencies": [i.original_data for i in bom_1.dependencies if i not in bom_2.dependencies]}
    return diff


def report_results(status: int, diffs: Dict, options: Options) -> None:
    if status == 0:
        print("No differences found.")
    else:
        print("Differences found.")
        handle_results(options.output, diffs)
    if options.bom_diff and options.output:
        report_file = options.output.replace(".json", "") + ".html"
        export_html_report(report_file, diffs, options)


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
