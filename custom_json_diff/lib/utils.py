import json
import logging
import os
import re
import sys
from datetime import date, datetime
from typing import Dict, List, TYPE_CHECKING

import packageurl
import semver
import toml
from jinja2 import Environment

if TYPE_CHECKING:
    from custom_json_diff.lib.custom_diff_classes import Options


logger = logging.getLogger(__name__)
recommendation_regex = re.compile(r"(?P<version>\d\S?.\d\S*)")


def compare_bom_refs(v1: str, v2: str, comparator: str = "<=") -> bool:
    """Compares bom-refs allowing new versions"""
    if not v1 or not v2:
        return v1==v2
    try:
        v1purl = packageurl.PackageURL.from_string(v1)
        v2purl = packageurl.PackageURL.from_string(v2)
        v1p = f"{v1purl.type}.{v1purl.namespace}.{v1purl.name}"
        v2p = f"{v2purl.type}.{v2purl.namespace}.{v2purl.name}"
        v1v, v2v = v1purl.version, v2purl.version
    except ValueError:
        if "@" in v1 and "@" in v2:
            v1p, v1v = split_bom_ref(v1)
            v2p, v2v = split_bom_ref(v2)
        else:
            logger.warning("Could not parse one or more of these bom-refs: %s, %s", v1, v2)
            return v1== v2
    return v1p == v2p and compare_versions(v1v, v2v, comparator)


def compare_date(dt1: str, dt2: str, comparator: str):
    """Compares two dates"""
    if not dt1 and not dt2:
        return True
    elif not dt1 or not dt2:
        return False
    try:
        date_1 = datetime.fromisoformat(dt1).date()
        date_2 = datetime.fromisoformat(dt2).date()
        return compare_generic(date_1, date_2, comparator)
    except ValueError:
        return False


def compare_generic(version_1: str | date | semver.Version, version_2: str | date | semver.Version, comparator):
    match comparator:
        case "<":
            return version_1 < version_2  #type: ignore
        case ">":
            return version_1 > version_2  #type: ignore
        case "<=":
            return version_1 <= version_2  #type: ignore
        case ">=":
            return version_1 >= version_2  #type: ignore
        case _:
            return version_1 == version_2  #type: ignore


def compare_recommendations(v1: str, v2: str, comparator: str):
    m1 = recommendation_regex.search(v1)
    m2 = recommendation_regex.search(v2)
    if m1 and m2:
        return compare_versions(m1["version"], m2["version"], comparator)
    logger.debug("Could not parse one or more of these recommendations: %s, %s", v1, v2)
    return v1 == v2


def compare_versions(v1: str|None, v2: str|None, comparator: str) -> bool:
    if not v1 and not v2:
        return True
    elif not v1 or not v2:
        return False
    v1 = v1.lstrip("v").rstrip(".") if v1 else ""
    v2 = v2.lstrip("v").rstrip(".") if v2 else ""
    try:
        version_1: str|semver.Version|None = semver.Version.parse(v1)
        version_2: str|semver.Version|None = semver.Version.parse(v2)
    except ValueError:
        logger.debug("Could not parse one or more of these versions: %s, %s", v1, v2)
        version_1, version_2 = v1, v2
    except TypeError:
        logger.debug("Could not parse one or more of these versions: %s, %s", v1, v2)
        return False
    return compare_generic(version_1, version_2, comparator)  #type: ignore


def export_html_report(outfile: str, diffs: Dict, options: "Options", status: int,
                       stats_summary: Dict) -> None:
    if options.report_template:
        template_file = options.report_template
    else:
        template_file = options.report_template or os.path.join(
                    os.path.dirname(os.path.realpath(__file__)), "bom_diff_template.j2")
    with open(template_file, "r", encoding="utf-8") as tmpl_file:
        template = tmpl_file.read()
    jinja_env = Environment(autoescape=False)
    jinja_tmpl = jinja_env.from_string(template)
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
        common_vdrs=diffs["common_summary"].get("vulnerabilities", []),
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
        diff_vdrs_1=diffs["diff_summary"].get(options.file_1, {}).get("vulnerabilities", []),
        diff_vdrs_2=diffs["diff_summary"].get(options.file_2, {}).get("vulnerabilities", []),
        bom_1=options.file_1,
        bom_2=options.file_2,
        stats=stats_summary,
        metadata=metadata_results,
        diff_status=status,
    )
    with open(outfile, "w", encoding="utf-8") as f:
        f.write(report_result)
    logger.debug(f"HTML report generated: {outfile}")


def export_results(outfile: str, diffs: Dict) -> None:
    with open(outfile, "w", encoding="utf-8") as f:
        f.write(json.dumps(diffs, indent=2))
    logger.debug(f"JSON report generated: {outfile}")


def get_sort_key(data: Dict, sort_keys: List[str]) -> str | bool:
    return next((i for i in sort_keys if i in data), False)


def import_config(config: str) -> Dict:
    with open(config, "r", encoding="utf-8") as f:
        try:
            toml_data = toml.load(f)
        except toml.TomlDecodeError:
            logger.error("Invalid TOML.")
            sys.exit(1)
    return toml_data


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


def split_bom_ref(bom_ref):
    if bom_ref.count("@") == 1:
        package, version = bom_ref.split("@")
    else:
        elements = bom_ref.split("@")
        version = elements.pop(-1)
        package = "".join(elements)
    return package, version
