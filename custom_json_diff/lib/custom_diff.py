import json
import logging
import re
import sys
from copy import deepcopy
from typing import Dict, List, Set, Tuple, TYPE_CHECKING

from json_flatten import flatten  # type: ignore

from custom_json_diff.lib.custom_diff_classes import (
    BomDicts, CsafDicts, FlatDicts, Options, order_documents
)
from custom_json_diff.lib.utils import (
    export_html_report, filter_empty, json_dump, json_load, sort_dict, sort_dict_lists
)

if TYPE_CHECKING:
    from custom_json_diff.lib.custom_diff_classes import (
        BomComponent, BomDependency, BomService, BomVdr
    )


logger = logging.getLogger(__name__)
purl_regex = re.compile(r"[^/]+/[^/]+@[^?\s]+")


def add_short_ref_for_report(diffs: Dict, options: "Options") -> Dict:
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


def check_in_commons(file_1: List, commons: List, i: "BomComponent|BomDependency|BomService|BomVdr"):
    if i not in commons:
        return 1 if i in file_1 else 2
    return 3


def check_regex(regex_keys: Set[re.Pattern], key: str) -> bool:
    return any(regex.match(key) for regex in regex_keys)


def compare_dicts(options: "Options") -> Tuple[int, "BomDicts|CsafDicts|FlatDicts", "BomDicts|CsafDicts|FlatDicts"]:
    options2 = deepcopy(options)
    json_1_data = json_to_class(options.file_1, options)
    json_2_data = json_to_class(options.file_2, options2)
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


def generate_bom_diff(bom: BomDicts, commons: BomDicts, common_refs: Dict) -> Dict:
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
    diff_summary["misc_data"] = (bom.misc_data - commons.misc_data).to_dict()
    return diff_summary


def generate_csaf_diff(csaf: CsafDicts, commons: CsafDicts, common_refs: Dict[str, Set]) -> Dict:
    return {
        csaf.filename: {
            "document": (csaf.document - commons.document).to_dict(),
            "product_tree": (csaf.product_tree - commons.product_tree).to_dict(),
            "vulnerabilities": [
                i.to_dict() for i in csaf.vulnerabilities
                if i.title not in common_refs["vulnerabilities"]
            ]
        }
    }


def get_diff(j1: "FlatDicts", j2: "FlatDicts", options: "Options") -> Dict:
    diff_1 = (j1 - j2).to_dict(unflat=True)
    diff_2 = (j2 - j1).to_dict(unflat=True)
    return {options.file_1: diff_1, options.file_2: diff_2}


def get_second_bom_diff(bom_1: BomDicts, bom_2: BomDicts, commons: BomDicts) -> Tuple[BomDicts, BomDicts]:
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
    return commons, BomDicts(bom_2.options, bom_2.filename, {},
                             other_data=bom_2.misc_data - bom_1.misc_data, components=components,
                             services=services, dependencies=dependencies, vulnerabilities=vdrs)


def get_second_csaf_diff(csaf_1: CsafDicts, csaf_2: CsafDicts, commons: CsafDicts) -> Tuple[CsafDicts, CsafDicts]:
    vulnerabilities = []
    for i in csaf_2.vulnerabilities:
        if (res := check_in_commons(csaf_1.vulnerabilities, commons.vulnerabilities, i)) == 1:
            commons.vulnerabilities.append(i)
        elif res == 2:
            vulnerabilities.append(i)
    return commons, CsafDicts(csaf_2.options, csaf_2.filename, {},
                              document=csaf_2.document - csaf_1.document,
                              product_tree=csaf_2.product_tree - csaf_1.product_tree,
                              vulnerabilities=vulnerabilities)


def get_bom_status(diff: Dict) -> int:
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
    if status == 0 and diff.get("misc_data"):
        status = 2
    return status


def get_csaf_status(diff: Dict) -> int:
    for key, value in diff.items():
        if value:
            return 3
    return 0


def json_to_class(json_file: str, options: "Options") -> "BomDicts|CsafDicts|FlatDicts":
    data = json.loads(json.dumps(json_load(json_file), sort_keys=True))
    if not data:
        logger.error("No data in JSON: %s.", json_file)
        logger.error("Rerun with --debug for more information.")
        sys.exit(1)
    if options.preconfig_type == "bom":
        data = sort_dict_lists(data, options.sort_keys)
        data = filter_dict(data, options).to_dict(unflat=True)
        return BomDicts(options, json_file, data)
    if options.preconfig_type == "csaf":
        data = sort_dict_lists(data, options.sort_keys)
        data = filter_dict(data, options).to_dict(unflat=True)
        return CsafDicts(options, json_file, data)
    return filter_dict(data, options)


def parse_purls(deps: List[Dict], regex: re.Pattern) -> List[Dict]:
    for i in deps:
        i["short_ref"] = match[0] if (match := regex.findall(i["ref"])) else i["ref"]
    return deps


def perform_bom_diff(bom_1: BomDicts, bom_2: BomDicts) -> Tuple[int, Dict]:
    b1, b2 = order_documents(bom_1, bom_2)
    common_bom = b1.intersection(b2, "common_summary")
    output = common_bom.to_summary()
    status, diffs = summarize_bom_diffs(b1, b2, common_bom)
    output |= {"diff_summary": diffs}
    return status, output


def perform_csaf_diff(csaf_1: CsafDicts, csaf_2: CsafDicts) -> Tuple[int, Dict]:
    c1, c2 = order_documents(csaf_1, csaf_2)
    common_csaf = c1.intersection(c2, "common_summary")
    output = common_csaf.to_summary()
    status, diffs = summarize_csaf_diffs(c1, c2, common_csaf)
    output |= {"diff_summary": diffs}
    return status, output


def report_results(status: int, diffs: Dict, options: Options, j1: BomDicts, j2: BomDicts) -> None:
    if status == 0:
        logger.info("No differences found.")
    else:
        logger.info("Differences found.")
    diffs = sort_dict(diffs, options.sort_keys)
    if options.preconfig_type:
        report_file = options.output.replace(".json", "") + ".html"
        if options.preconfig_type == "bom":
            export_html_report(report_file, add_short_ref_for_report(diffs, options), options, status,
                           calculate_pcts(diffs, j1, j2))
            diffs = unpack_misc_data(diffs, j1.options)
        elif options.preconfig_type == "csaf":
            export_html_report(report_file, diffs, options, status)
    if options.output:
        if not options.include_empty:
            diffs = filter_empty(options.include_empty, diffs)
        json_dump(options.output, diffs,
                   error_msg=f"Failed to export diff results to {options.output}.",
                   success_msg=f"Diff results written to {options.output}.")
    else:
        logger.warning("No output file specified. No reports generated.")


def unpack_misc_data(diffs: Dict, options: "Options") -> Dict:
    if misc_data := diffs["common_summary"].get("misc_data"):
        diffs["common_summary"] |= {**misc_data}
        del diffs["common_summary"]["misc_data"]
    if misc_data := diffs["diff_summary"].get(options.file_1, {}).get("misc_data"):
        diffs["diff_summary"][options.file_1] |= {**misc_data}
        del diffs["diff_summary"][options.file_1]["misc_data"]
    if misc_data := diffs["diff_summary"].get(options.file_2, {}).get("misc_data"):
        diffs["diff_summary"][options.file_2] |= {**misc_data}
        del diffs["diff_summary"][options.file_2]["misc_data"]
    return sort_dict(diffs, options.sort_keys)


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


def summarize_bom_diffs(bom_1: BomDicts, bom_2: BomDicts, commons: BomDicts) -> Tuple[int, Dict]:
    commons_2, bom_2 = get_second_bom_diff(bom_1, bom_2, commons)
    common_refs = commons_2.get_refs()
    summary_1 = generate_bom_diff(bom_1, commons, common_refs)
    summary_2 = generate_bom_diff(bom_2, commons_2, common_refs)
    status = max(get_bom_status(summary_1), get_bom_status(summary_2))
    return status, {bom_1.filename: summary_1, bom_2.filename: summary_2}


def summarize_csaf_diffs(csaf_1: CsafDicts, csaf_2: CsafDicts, commons: CsafDicts) -> Tuple[int, Dict]:
    commons, csaf_1 = get_second_csaf_diff(csaf_2, csaf_1, commons)
    commons_2, csaf_2 = get_second_csaf_diff(csaf_1, csaf_2, commons)
    common_refs = commons_2.get_refs()
    diff_summary = generate_csaf_diff(csaf_1, commons, common_refs)
    diff_summary |= generate_csaf_diff(csaf_2, commons_2, common_refs)
    status = max(get_csaf_status(diff_summary[csaf_1.filename]), get_csaf_status(diff_summary[csaf_2.filename]))
    return status, diff_summary
