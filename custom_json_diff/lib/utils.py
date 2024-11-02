import json
import logging
import os
import re
import sys
from datetime import date, datetime
from typing import Any, Dict, List, TYPE_CHECKING

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
        return compare_generic(v1, v2, comparator)
    try:
        v1purl = packageurl.PackageURL.from_string(v1)
        v2purl = packageurl.PackageURL.from_string(v2)
        v1p = f"{v1purl.type}.{v1purl.namespace}.{v1purl.name}"
        v2p = f"{v2purl.type}.{v2purl.namespace}.{v2purl.name}"
        v1v, v2v = v1purl.version, v2purl.version
    except ValueError:
        v1p, v1v = split_bom_ref(v1)
        v2p, v2v = split_bom_ref(v2)
    return v1p == v2p and compare_versions(v1v, v2v, comparator)


def compare_date(dt1: str, dt2: str, comparator: str):
    """Compares two dates"""
    if not dt1 and not dt2:
        return compare_generic(dt1, dt2, comparator)
    elif not dt1 or not dt2:
        return False
    try:
        date_1 = datetime.fromisoformat(dt1).date()
        date_2 = datetime.fromisoformat(dt2).date()
        return compare_generic(date_1, date_2, comparator)
    except ValueError:
        return compare_generic(dt1, dt2, comparator)


def compare_generic(a: str | date | semver.Version, b: str | date | semver.Version, comparator):
    if isinstance(a, str) and a.isnumeric() and isinstance(b, str) and b.isnumeric():
        a = int(a)  #type: ignore
        b = int(b)  #type: ignore
    try:
        match comparator:
            case "<":
                return a < b  #type: ignore
            case ">":
                return a > b  #type: ignore
            case "<=":
                return a <= b  #type: ignore
            case ">=":
                return a >= b  #type: ignore
            case _:
                return a == b  #type: ignore
    except TypeError:
        return compare_generic(str(a), str(b), comparator)


def compare_recommendations(v1: str, v2: str, comparator: str):
    if v1 and v2:
        m1 = recommendation_regex.search(v1)
        m2 = recommendation_regex.search(v2)
        if m1 and m2:
            return compare_versions(m1["version"], m2["version"], comparator)
    elif not v1 and not v2:
        return compare_generic(v1, v2, comparator)
    logger.debug("Could not extract one or more of these recommendations: %s, %s", v1, v2)
    return compare_generic(v1, v2, comparator)


def compare_versions(v1: str|None, v2: str|None, comparator: str) -> bool:
    if not v1 and not v2:
        return compare_generic("", "", comparator)
    elif not v1 or not v2:
        return False
    v1 = v1.lstrip("v").rstrip(".") if v1 else ""
    v2 = v2.lstrip("v").rstrip(".") if v2 else ""
    try:
        version_1: str|semver.Version|None = semver.Version.parse(v1)
        version_2: str|semver.Version|None = semver.Version.parse(v2)
    except ValueError:
        logger.debug("Could not parse one or more of these versions: %s, %s", v1, v2)
        return manual_version_compare(v1, v2, comparator)
    return compare_generic(version_1, version_2, comparator)  #type: ignore


def export_html_report(outfile: str, diffs: Dict, options: "Options", status: int,
                       stats_summary: Dict | None = None) -> None:
    if options.report_template:
        template_file = options.report_template
    else:
        template_file = options.report_template or os.path.join(os.path.dirname(os.path.realpath(__file__)), f"{options.preconfig_type}_diff_template.j2")
    template = file_read(template_file)
    jinja_env = Environment(autoescape=True)
    jinja_tmpl = jinja_env.from_string(str(template))
    try:
        if options.preconfig_type == "bom":
            report_result = render_bom_template(diffs, jinja_tmpl, options, stats_summary, status)
        else:
            report_result = render_csaf_template(diffs, jinja_tmpl, options, status)
    except TypeError:
        logger.warning(f"Could not render html report for {options.file_1} and {options.file_2} BOM diff. Likely an expected key is missing.")
        return
    file_write(outfile, report_result, error_msg=f"Unable to generate HTML report at {outfile}.",
               success_msg=f"HTML report generated: {outfile}")


def file_read(filename: str | bytes, binary: bool = False, error_msg: str = "", log: logging.Logger = logger) -> str | bytes:
    try:
        if binary:
            with open(filename, "rb") as f:
                return f.read()
        with open(filename, "r", encoding="utf-8") as f:
            return f.read()
    except (FileNotFoundError, IsADirectoryError) as e:
        if error_msg:
            log.debug(error_msg)
        else:
            log.debug(e)
    return ""


def file_write(filename: str | bytes, contents, error_msg: str = "", success_msg: str = "", log: logging.Logger = logger) -> None:
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(contents)
    except OSError as e:
        if error_msg:
            log.debug(error_msg)
        else:
            log.debug(e)
    else:
        if success_msg:
            log.info(success_msg)
        else:
            log.debug("File written: %s", filename)


def recursive_remove_empty(d: Dict) -> Dict:
    filtered = {}
    for k, v in d.items():
        if not v:
            continue
        if isinstance(v, dict):
            filtered[k] = recursive_remove_empty(v)
        elif isinstance(v, list):
            flist = []
            for i in v:
                if isinstance(i, dict):
                    if tmp := recursive_remove_empty(i):
                        flist.append(tmp)
                elif i:
                    flist.append(i)
            if flist:
                filtered[k] = flist  # type: ignore
        else:
            filtered[k] = v
    return filtered


def filter_empty(include_empty: bool, d: Dict) -> Dict:
    return d if include_empty else recursive_remove_empty(d)


def get_sort_key(data: Dict, sort_keys: List[str]) -> str | bool:
    return next((i for i in sort_keys if i in data), False)


def get_sort_key_list(data: List[Dict], sort_keys: List):
    sort_keys = sort_keys
    if not (key := get_sort_key(data[0], list(sort_keys))):
        return False
    key_list = [(i.keys()) for i in data]
    if all(key in i for i in key_list):
        return key
    sort_keys.pop(sort_keys.index(key))
    return get_sort_key_list(data, list(sort_keys))


def import_config(config: str) -> Dict:
    file_data = file_read(config, False, f"Unable to locate {config}.")
    try:
        toml_data = toml.loads(str(file_data))
        if toml_data.get("preset_settings") and toml_data["preset_settings"].get("type", "") not in {
            "bom", "csaf"}:
            raise ValueError("Invalid preset type.")
    except toml.TomlDecodeError:
        logger.error("Invalid TOML.")
        sys.exit(1)
    except ValueError as e:
        logger.error(e)
        sys.exit(1)
    return toml_data


def json_load(json_file: str, error_msg: str = "", log: logging.Logger = logger) -> Dict:
    try:
        return json.loads(file_read(json_file, False, error_msg, log))
    except json.JSONDecodeError as e:
        log.debug(e)
        if error_msg:
            log.warning(error_msg)
    return {}


def json_dump(filename: str, data: Dict, compact: bool = False, error_msg: str = "", success_msg: str = "", sort_keys: List|None = None, log: logging.Logger = logger) -> None:
    if sort_keys:
        data = sort_dict(data, sort_keys)
    try:
        if compact:
            formatted = json.dumps(data, separators=(',', ':'), sort_keys=True)
        else:
            formatted = json.dumps(data, indent=2, sort_keys=True)
    except TypeError as e:
        if error_msg:
            log.warning(error_msg)
        log.debug(e)
        return
    file_write(filename, formatted, error_msg=error_msg, success_msg=success_msg, log=log)


def manual_version_compare(v1: str, v2: str, comparator: str) -> bool:
    if ("." not in v1 and "-" not in v1) or ("." not in v2 and "-" not in v2):
        return compare_generic(v1, v2, comparator)
    version_1 = v1.replace("-", ".").split(".")
    version_2 = v2.replace("-", ".").split(".")
    if (v1_len := len(version_1)) != (v2_len := len(version_2)):
        if v1_len > v2_len:
            diff_len = v1_len - v2_len
            version_2.extend(["0"] * diff_len)
        else:
            diff_len = v2_len - v1_len
            version_1.extend(["0"] * diff_len)
    if comparator in ("<", ">"):
        return manual_version_compare_noeq(version_1, version_2, comparator)
    for i, v in enumerate(version_1):
        if compare_generic(v, version_2[i], comparator[0]):
            return True
        if not compare_generic(v, version_2[i], comparator):
            return False
    return True


def manual_version_compare_noeq(v1: List, v2: List, comparator: str) -> bool:
    for i, v in enumerate(v1):
        if compare_generic(v, v2[i], comparator):
            return True
    return False


def render_bom_template(diffs, jinja_tmpl, options, stats_summary, status):
    return jinja_tmpl.render(
        common_lib=diffs["common_summary"].get("components", {}).get("libraries", []),
        common_frameworks=diffs["common_summary"].get("components", {}).get("frameworks", []),
        common_services=diffs["common_summary"].get("services", []),
        common_deps=diffs["common_summary"].get("dependencies", []),
        common_apps=diffs["common_summary"].get("components", {}).get("applications", []),
        common_other=diffs["common_summary"].get("components", {}).get("other_components", []),
        common_vdrs=diffs["common_summary"].get("vulnerabilities", []),
        common_misc_data=json.dumps(diffs["common_summary"]["misc_data"]).replace("\\n", " ") if diffs["common_summary"].get("misc_data") else None,
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
        misc_data_1=json.dumps(diffs["diff_summary"][options.file_1]["misc_data"]).replace("\\n", " ") if diffs["diff_summary"].get(options.file_1, {}).get("misc_data", {}) else None,
        misc_data_2=json.dumps(diffs["diff_summary"][options.file_2]["misc_data"]).replace("\\n", " ") if diffs["diff_summary"].get(options.file_2, {}).get("misc_data", {}) else None,
        bom_1=options.file_1,
        bom_2=options.file_2,
        stats=stats_summary,
        diff_status=status,
    )


def render_csaf_template(diffs, jinja_tmpl, options, status):
    return jinja_tmpl.render(
            common_document=diffs["common_summary"].get("document", {}),
            common_product_tree=diffs["common_summary"].get("product_tree", {}),
            common_vulnerabilities=diffs["common_summary"].get("vulnerabilities", []),
            diff_document_1=diffs["diff_summary"].get(options.file_1, {}).get("document", {}),
            diff_document_2=diffs["diff_summary"].get(options.file_2, {}).get("document", {}),
            diff_product_tree_1=diffs["diff_summary"].get(options.file_1, {}).get("product_tree", {}),
            diff_product_tree_2=diffs["diff_summary"].get(options.file_2, {}).get("product_tree", {}),
            diff_vulnerabilities_1=diffs["diff_summary"].get(options.file_1, {}).get("vulnerabilities", []),
            diff_vulnerabilities_2=diffs["diff_summary"].get(options.file_2, {}).get("vulnerabilities", []),
            diff_status=status,
            csaf_1=options.file_1,
            csaf_2=options.file_2,
        )


def sort_dict(result: Dict, sort_keys: List[str]) -> Dict:
    """Sorts a dictionary"""
    for k, v in result.items():
        if isinstance(v, dict):
            result[k] = sort_dict_lists(v, sort_keys)
        elif isinstance(v, list) and len(v) >= 2:
            result[k] = sort_list(v, sort_keys)
        else:
            result[k] = v
    return result


# deprecated
def sort_dict_lists(result: Dict, sort_keys: List[str]) -> Dict:
    return sort_dict(result, sort_keys)


def sort_helper(v: Any, sort_keys: List) -> Any:
    if isinstance(v, list) and len(v) >= 2:
        v = sort_list(v, sort_keys)
    elif isinstance(v, dict):
        v = sort_dict_lists(v, sort_keys)
    return v


def sort_list(lst: List, sort_keys: List[str]) -> List:
    """Sorts a list"""
    if isinstance(lst[0], dict):
        if sort_key := get_sort_key_list(lst, sort_keys):
            lst = sorted(lst, key=lambda x: x[sort_key])
        for i in lst:
            for k, v in i.items():
                i[k] = sort_helper(v, sort_keys)
        logger.debug("No key(s) specified for sorting. Cannot sort list of dictionaries.")
        return lst
    if isinstance(lst[0], (str, int)):
        lst.sort()
    return lst


def split_bom_ref(bom_ref: str):
    if "@" not in bom_ref:
        return bom_ref, ""
    if bom_ref.count("@") == 1:
        package, version = bom_ref.split("@")
    else:
        elements = bom_ref.split("@")
        version = elements.pop(-1)
        package = "".join(elements)
    if "?" in version:
        version = version.split("?")[0]
    return package, version.lstrip("v")
