import json
import logging
import os
import re
import sys
from copy import deepcopy
from typing import Dict, List, Set, Tuple

from jinja2 import Environment
from json_flatten import flatten, unflatten  # type: ignore

from custom_json_diff.custom_diff_classes import BomDicts, FlatDicts, Options


logger = logging.getLogger(__name__)


def calculate_pcts(diffs: Dict, j1: BomDicts, j2: BomDicts) -> Dict:
    j1_counts = j1.generate_counts()
    j2_counts = j2.generate_counts()
    common_counts = generate_counts(diffs["common_summary"])
    result = []
    for key, value in common_counts.items():
        total = j1_counts[key] + j2_counts[key]
        if total != 0:
            result.append([f"Common {key} matched: ", f"{value} ({round(((value*2)/total) * 100, 2)})%"])

    result_2 = summarize_diffs({}, generate_counts(diffs["diff_summary"][j1.filename]), j1_counts, common_counts)
    result_2 = summarize_diffs(result_2, generate_counts(diffs["diff_summary"][j2.filename]), j2_counts, common_counts)
    return {"common_summary": result, "breakdown": result_2}


def check_regex(regex_keys: Set[re.Pattern], key: str) -> bool:
    return any(regex.match(key) for regex in regex_keys)


def compare_dicts(options: Options) -> Tuple[int, FlatDicts | BomDicts, FlatDicts | BomDicts]:
    options2 = deepcopy(options)
    json_1_data = load_json(options.file_1, options)
    json_2_data = load_json(options.file_2, options2)
    if json_1_data == json_2_data:
        return 0, json_1_data, json_2_data
    else:
        return 1, json_1_data, json_2_data


def export_html_report(outfile: str, diffs: Dict, j1: BomDicts, j2: BomDicts, options: Options) -> None:
    if options.report_template:
        template_file = options.report_template
    else:
        template_file = options.report_template or os.path.join(
                    os.path.dirname(os.path.realpath(__file__)), "bom_diff_template.j2")
    with open(template_file, "r", encoding="utf-8") as tmpl_file:
        template = tmpl_file.read()
    jinja_env = Environment(autoescape=False)
    jinja_tmpl = jinja_env.from_string(template)
    purl_regex = re.compile(r"[^/]+/[^/]+@[^?\s]+")
    diffs["diff_summary"][options.file_1]["dependencies"] = parse_purls(
        diffs["diff_summary"][options.file_1].get("dependencies", []), purl_regex)
    diffs["diff_summary"][options.file_2]["dependencies"] = parse_purls(
        diffs["diff_summary"][options.file_2].get("dependencies", []), purl_regex)
    diffs["common_summary"]["dependencies"] = parse_purls(
        diffs["common_summary"].get("dependencies", []), purl_regex)
    stats_summary = calculate_pcts(diffs, j1, j2)
    metadata_results = bool(
        diffs["diff_summary"][options.file_1].get("misc_data", {}) or
        diffs["diff_summary"][options.file_2].get("misc_data", {})
    )
    report_result = jinja_tmpl.render(
        common_lib=diffs["common_summary"].get("components", {}).get("libraries", []),
        common_frameworks=diffs["common_summary"].get("components", {}).get("frameworks", []),
        common_services=diffs["common_summary"].get("services", []),
        common_deps=diffs["common_summary"].get("dependencies", []),
        common_apps=diffs["common_summary"].get("components", {}).get("applications", []),
        common_other=diffs["common_summary"].get("components", {}).get("other_components", []),
        diff_lib_1=diffs["diff_summary"].get(options.file_1, {}).get("components", {}).get("libraries", []),
        diff_lib_2=diffs["diff_summary"].get(options.file_2, {}).get("components", {}).get("libraries", []),
        diff_frameworks_1=diffs["diff_summary"].get(options.file_1, {}).get("components", {}).get("frameworks", []),
        diff_frameworks_2=diffs["diff_summary"].get(options.file_2, {}).get("components", {}).get("frameworks", []),
        diff_apps_1=diffs["diff_summary"].get(options.file_1, {}).get("components", {}).get("applications", []),
        diff_apps_2=diffs["diff_summary"].get(options.file_2, {}).get("components", {}).get("applications", []),
        diff_other_1=diffs["diff_summary"].get(options.file_1, {}).get("components", {}).get("other_components", []),
        diff_other_2=diffs["diff_summary"].get(options.file_2, {}).get("components", {}).get("other_components", []),
        diff_services_1=diffs["diff_summary"].get(options.file_1, {}).get("services", []),
        diff_services_2=diffs["diff_summary"].get(options.file_2, {}).get("services", []),
        diff_deps_1=diffs["diff_summary"].get(options.file_1, {}).get("dependencies", []),
        diff_deps_2=diffs["diff_summary"].get(options.file_2, {}).get("dependencies", []),
        bom_1=options.file_1,
        bom_2=options.file_2,
        stats=stats_summary,
        comp_only=options.comp_only,
        metadata=metadata_results,
    )
    with open(outfile, "w", encoding="utf-8") as f:
        f.write(report_result)
    logger.debug(f"HTML report generated: {outfile}")


def export_results(outfile: str, diffs: Dict) -> None:
    with open(outfile, "w", encoding="utf-8") as f:
        f.write(json.dumps(diffs, indent=2))
    logger.debug(f"JSON report generated: {outfile}")


def filter_dict(data: Dict, options: Options) -> FlatDicts:
    data = flatten(sort_dict_lists(data, options.sort_keys))
    return FlatDicts(data).filter_out_keys(options.exclude)


def generate_counts(data: Dict) -> Dict:
    return {"libraries": len(data.get("components", {}).get("libraries", [])),
              "frameworks": len(data.get("components", {}).get("frameworks", [])),
              "applications": len(data.get("components", {}).get("applications", [])),
              "other_components": len(data.get("components", {}).get("other_components", [])),
              "services": len(data.get("services", [])), "dependencies": len(data.get("dependencies", []))}


def get_diff(j1: FlatDicts, j2: FlatDicts, options: Options) -> Dict:
    diff_1 = (j1 - j2).to_dict(unflat=True)
    diff_2 = (j2 - j1).to_dict(unflat=True)
    return {options.file_1: diff_1, options.file_2: diff_2}


def get_sort_key(data: Dict, sort_keys: List[str]) -> str | bool:
    return next((i for i in sort_keys if i in data), False)


def handle_results(outfile: str, diffs: Dict) -> None:
    if outfile:
        export_results(outfile, diffs)


def load_json(json_file: str, options: Options) -> FlatDicts | BomDicts:
    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            data = json.loads(json.dumps(data, sort_keys=True))
    except FileNotFoundError:
        logger.error("File not found: %s", json_file)
        sys.exit(1)
    except json.JSONDecodeError:
        logger.error("Invalid JSON: %s", json_file)
        sys.exit(1)
    if options.bom_diff:
        data = sort_dict_lists(data, ["url", "content", "ref", "name", "value"])
        data = filter_dict(data, options).to_dict(unflat=True)
        return BomDicts(options, json_file, data, {})
    return filter_dict(data, options)


def parse_purls(deps: List[Dict], regex: re.Pattern) -> List[Dict]:
    for i in deps:
        i["short_ref"] = match[0] if (match := regex.findall(i["ref"])) else i["ref"]
    return deps


def perform_bom_diff(bom_1: BomDicts, bom_2: BomDicts) -> Dict:
    output = (bom_1.intersection(bom_2, "common_summary")).to_summary()
    output |= {
        "diff_summary": (bom_1 - bom_2).to_summary()
    }
    output["diff_summary"] |= (bom_2 - bom_1).to_summary()
    return output


def report_results(status: int, diffs: Dict, options: Options, j1: BomDicts | None = None, j2: BomDicts | None = None) -> None:
    if status == 0:
        print("No differences found.")
    else:
        print("Differences found.")
        handle_results(options.output, diffs)
    if not options.output:
        logger.warning("No output file specified. No reports generated.")
        return
    elif options.bom_diff:
        report_file = options.output.replace(".json", "") + ".html"
        export_html_report(report_file, diffs, j1, j2, options)  # type: ignore


def sort_dict_lists(result: Dict, sort_keys: List[str]) -> Dict:
    """Sorts a dictionary"""
    for k, v in result.items():
        if isinstance(v, dict):
            result[k] = sort_dict_lists(v, sort_keys)
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
        logger.debug("No key(s) specified for sorting. Cannot sort list of dictionaries.")
        return lst
    if isinstance(lst[0], (str, int)):
        lst.sort()
    return lst


def summarize_diffs(result: Dict, diff_counts: Dict, bom_counts: Dict, common_counts: Dict) -> Dict:
    for key, value in diff_counts.items():
        if bom_counts[key] != 0:
            found = bom_counts[key] - common_counts.get(key, 0)
            if result.get(key):
                result[key].append(f"{found}/{bom_counts[key]} ({round((found / bom_counts[key]) * 100, 2)}%)")
            else:
                result[key] = [f"{found}/{bom_counts[key]} ({round((found / bom_counts[key]) * 100, 2)}%)"]
    return result
