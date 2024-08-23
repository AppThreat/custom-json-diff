import json
import logging
import re
import sys
from copy import deepcopy
from typing import Dict, List, Set, Tuple, TYPE_CHECKING

from json_flatten import flatten  # type: ignore

from custom_json_diff.lib.custom_diff_classes import BomDicts, FlatDicts, Options, order_boms
from custom_json_diff.lib.utils import (
    export_html_report, export_results, logger, sort_dict_lists
)

if TYPE_CHECKING:
    from custom_json_diff.lib.custom_diff_classes import (
        BomComponent, BomDependency, BomService, BomVdr
    )


logger = logging.getLogger(__name__)


def add_short_ref_for_report(diffs: Dict, options: "Options") -> Dict:
    purl_regex = re.compile(r"[^/]+/[^/]+@[^?\s]+")
    diffs["diff_summary"][options.file_1]["dependencies"] = parse_purls(
        diffs["diff_summary"][options.file_1].get("dependencies", []), purl_regex)
    diffs["diff_summary"][options.file_2]["dependencies"] = parse_purls(
        diffs["diff_summary"][options.file_2].get("dependencies", []), purl_regex)
    diffs["common_summary"]["dependencies"] = parse_purls(
        diffs["common_summary"].get("dependencies", []), purl_regex)
    return diffs


def calculate_pcts(diffs: Dict, j1: BomDicts, j2: BomDicts) -> Dict:
    j1_counts = j1.generate_comp_counts()
    j2_counts = j2.generate_comp_counts()
    common_counts = generate_counts(diffs["common_summary"])
    result = []
    for key, value in common_counts.items():
        total = j1_counts[key] + j2_counts[key]
        if total != 0:
            pct = min(100.00, round((value / (total / 2)) * 100, 2))
            result.append([f"Common {key} matched: ", f"{value} ({pct})%"])
    result_2 = summarize_diff_counts(
        {}, generate_counts(diffs["diff_summary"][j1.filename]), j1_counts, common_counts)
    result_2 = summarize_diff_counts(
        result_2, generate_counts(diffs["diff_summary"][j2.filename]), j2_counts, common_counts)
    return {"common_summary": result, "breakdown": result_2}


def check_in_commons(bom_1: List, commons: List, i: "BomComponent|BomDependency|BomService|BomVdr"):
    if i not in commons:
        return 1 if i in bom_1 else 2
    return 3


def check_regex(regex_keys: Set[re.Pattern], key: str) -> bool:
    return any(regex.match(key) for regex in regex_keys)


def compare_dicts(options: "Options") -> Tuple[int, "FlatDicts|BomDicts", "FlatDicts|BomDicts"]:
    options2 = deepcopy(options)
    json_1_data = load_json(options.file_1, options)
    json_2_data = load_json(options.file_2, options2)
    if json_1_data == json_2_data:
        return 0, json_1_data, json_2_data
    return 1, json_1_data, json_2_data


def filter_dict(data: Dict, options: "Options") -> FlatDicts:
    data = flatten(sort_dict_lists(data, options.sort_keys))
    return FlatDicts(data).filter_out_keys(options.exclude)


def generate_counts(data: Dict) -> Dict:
    return {"libraries": len(data.get("components", {}).get("libraries", [])),
            "frameworks": len(data.get("components", {}).get("frameworks", [])),
            "applications": len(data.get("components", {}).get("applications", [])),
            "other_components": len(data.get("components", {}).get("other_components", [])),
            "services": len(data.get("services", [])),
            "dependencies": len(data.get("dependencies", [])),
            "vulnerabilities": len(data.get("vulnerabilities", []))}


def generate_diff(bom: BomDicts, commons: BomDicts, common_refs: Dict) -> Dict:
    diff_summary = {
        "components": {"applications": [], "frameworks": [], "libraries": [],
                                   "other_components": []},
        "dependencies": [i.to_dict() for i in bom.dependencies if i.ref not in common_refs["dependencies"]],
        "services": [i.to_dict() for i in bom.services if i.search_key not in common_refs["services"]],
        "vulnerabilities": [i.to_dict() for i in bom.vdrs if i.bom_ref not in common_refs["vdrs"]]
    }
    for i in bom.components:
        if i.bom_ref not in common_refs["components"]:
            match i.component_type:
                case "application":
                    diff_summary["components"]["applications"].append(i.to_dict())  #type: ignore
                case "framework":
                    diff_summary["components"]["frameworks"].append(i.to_dict())  #type: ignore
                case "library":
                    diff_summary["components"]["libraries"].append(i.to_dict())  #type: ignore
                case _:
                    diff_summary["components"]["other_components"].append(i.to_dict())  #type: ignore
    diff_summary["misc_data"] = (bom.other_data - commons.other_data).to_dict()
    return diff_summary


def get_common_bom_refs(commons: BomDicts) -> Dict:
    return {
        "components": {i.bom_ref for i in commons.components},
        "dependencies": {i.ref for i in commons.dependencies},
        "services": {i.search_key for i in commons.services},
        "vdrs": {i.bom_ref for i in commons.vdrs}
    }


def get_diff(j1: "FlatDicts", j2: "FlatDicts", options: "Options") -> Dict:
    diff_1 = (j1 - j2).to_dict(unflat=True)
    diff_2 = (j2 - j1).to_dict(unflat=True)
    return {options.file_1: diff_1, options.file_2: diff_2}


def get_second_diff(bom_1: BomDicts, bom_2: BomDicts, commons: BomDicts) -> Tuple[BomDicts, BomDicts]:
    components = []
    services = []
    dependencies = []
    vdrs = []
    for i in bom_2.components:
        if (res := check_in_commons(bom_1.components, commons.components, i)) == 1:
            commons.components.append(i)
        elif res == 2:
            components.append(i)
    for i in bom_2.services:
        if (res := check_in_commons(bom_1.services, commons.services, i)) == 1:
            commons.services.append(i)
        elif res == 2:
            services.append(i)
    for i in bom_2.dependencies:
        if (res := check_in_commons(bom_1.dependencies, commons.dependencies, i)) == 1:
            commons.dependencies.append(i)
        elif res == 2:
            dependencies.append(i)
    for i in bom_2.vdrs:
        if (res := check_in_commons(bom_1.vdrs, commons.vdrs, i)) == 1:
            commons.vdrs.append(i)
        elif res == 2:
            vdrs.append(i)
    return commons, BomDicts(bom_2.options, bom_2.filename, {}, other_data=bom_2.other_data-bom_1.other_data, components=components, services=services, dependencies=dependencies, vulnerabilities=vdrs)


def get_status(diff: Dict) -> int:
    prelim_status = any((
        len(diff.get("components", {}).get("applications", [])) > 0,
        len(diff.get("components", {}).get("frameworks", [])) > 0,
        len(diff.get("components", {}).get("libraries", [])) > 0,
        len(diff.get("components", {}).get("other_components", [])) > 0,
        len(diff.get("dependencies", [])) > 0,
        len(diff.get("services", [])) > 0,
        len(diff.get("vulnerabilities", [])) > 0
    ))
    status = 3 if prelim_status else 0
    if status == 0 and diff.get("metadata"):
        status = 2
    return status


def handle_results(outfile: str, diffs: Dict) -> None:
    if outfile:
        export_results(outfile, diffs)


def load_json(json_file: str, options: "Options") -> "FlatDicts|BomDicts":
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
        data = sort_dict_lists(data, ["bom-ref", "cve", "id", "url", "text", "content", "ref", "name", "value"])
        data = filter_dict(data, options).to_dict(unflat=True)
        return BomDicts(options, json_file, data)
    return filter_dict(data, options)


def parse_purls(deps: List[Dict], regex: re.Pattern) -> List[Dict]:
    for i in deps:
        i["short_ref"] = match[0] if (match := regex.findall(i["ref"])) else i["ref"]
    return deps


def perform_bom_diff(bom_1: BomDicts, bom_2: BomDicts) -> Tuple[int, Dict]:
    b1, b2 = order_boms(bom_1, bom_2)
    common_bom = b1.intersection(b2, "common_summary")
    _, output = common_bom.to_summary()
    status, diffs = summarize_diffs(b1, b2, common_bom)
    return status, {**diffs, **output}


def report_results(status: int, diffs: Dict, options: Options, j1: BomDicts, j2: BomDicts) -> None:
    if status == 0:
        logger.info("No differences found.")
    else:
        logger.info("Differences found.")
    if options.output:
        export_results(options.output, diffs)
    else:
        logger.warning("No output file specified. No reports generated.")
        return
    if options.bom_diff:
        report_file = options.output.replace(".json", "") + ".html"
        export_html_report(report_file, add_short_ref_for_report(diffs, options), options, status,
                           calculate_pcts(diffs, j1, j2))


def summarize_diff_counts(result: Dict, diff_counts: Dict, bom_counts: Dict, common_counts: Dict) -> Dict:
    for key in diff_counts.keys():
        if bom_counts[key] != 0:
            found = bom_counts[key] - common_counts.get(key, 0)
            if not common_counts.get(key):
                found = bom_counts[key]
            found = max(found, 0)
            if result.get(key):
                result[key].append(f"{found}/{bom_counts[key]} ({round((found / bom_counts[key]) * 100, 2)}%)")
            else:
                result[key] = [f"{found}/{bom_counts[key]} ({round((found / bom_counts[key]) * 100, 2)}%)"]
    return result


def summarize_diffs(bom_1: BomDicts, bom_2: BomDicts, commons: BomDicts) -> Tuple[int, Dict]:
    commons_2, bom_2 = get_second_diff(bom_1, bom_2, commons)
    common_refs = get_common_bom_refs(commons_2)
    diff_summary_1 = generate_diff(bom_1, commons, common_refs)
    diff_summary_2 = generate_diff(bom_2, commons, common_refs)
    status = int(get_status(diff_summary_1) or get_status(diff_summary_2))
    return status, {"diff_summary": {bom_1.filename: diff_summary_1, bom_2.filename: diff_summary_2}}