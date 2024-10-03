import argparse
import logging

from importlib.metadata import version

from custom_json_diff.lib.custom_diff import (
    compare_dicts, get_diff, perform_bom_diff, perform_csaf_diff, report_results
)
from custom_json_diff.lib.custom_diff_classes import Options


logger = logging.getLogger(__name__)


def build_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="custom-json-diff")
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version="%(prog)s " + version("custom_json_diff")
    )
    parser.set_defaults(
        preconfig_diff_type="",
        allow_new_versions=False,
        report_template="",
        exclude=[],
        allow_new_data=False,
        include=[]
    )
    parser.add_argument(
        "-i",
        "--input",
        action="store",
        help="Two JSON files to compare - older file first.",
        required=True,
        nargs=2,
        dest="input",
    )
    parser.add_argument(
        "-o",
        "--output",
        action="store",
        help="Export JSON of differences to this file.",
        dest="output",
    )
    parser.add_argument(
        "-c",
        "--config-file",
        action="store",
        help="Import TOML configuration file (overrides commandline options).",
        dest="config"
    )
    subparsers = parser.add_subparsers(help="subcommand help")
    parser_pc_diff = subparsers.add_parser("preset-diff", help="Compare CycloneDX BOMs or Oasis CSAFs")
    parser_pc_diff.set_defaults(preset_type="")
    parser_pc_diff.add_argument(
        "--allow-new-versions",
        "-anv",
        action="store_true",
        help="BOM only - allow newer versions in second BOM to pass.",
        dest="allow_new_versions",
        default=False,
    )
    parser_pc_diff.add_argument(
        "--allow-new-data",
        "-and",
        action="store_true",
        help="Allow populated values in newer BOM or CSAF to pass against empty values in original BOM/CSAF.",
        dest="allow_new_data",
        default=False,
    )
    parser_pc_diff.add_argument(
        "--type",
        action="store",
        help="Either bom or csaf",
        dest="preset_type",
    )
    parser_pc_diff.add_argument(
        "-r",
        "--report-template",
        action="store",
        help="Jinja2 template to use for report generation.",
        dest="report_template",
        default="",
    )
    parser_pc_diff.add_argument(
        "--include-extra",
        action="store",
        help="BOM only - include properties/evidence/licenses/hashes/externalReferences (list which with comma, no space, inbetween).",
        dest="include",
    )
    parser_pc_diff.add_argument(
        "--include-empty",
        "-e",
        action="store_true",
        default=False,
        dest="include_empty",
        help="Include keys with empty values in summary.",
    )
    parser.add_argument(
        "-x",
        "--exclude",
        action="store",
        help="Exclude field(s) from comparison.",
        dest="exclude",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print debug messages.",
        dest="debug",
    )

    return parser.parse_args()


def main():
    args = build_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    exclude = args.exclude.split(",") if args.exclude else []
    include = args.include.split(",") if args.include else []
    preset_type = args.preset_type.lower()
    if preset_type and preset_type not in ("bom", "csaf"):
        raise ValueError("Preconfigured type must be either bom or csaf.")
    options = Options(
        allow_new_versions=args.allow_new_versions,
        allow_new_data=args.allow_new_data,
        config=args.config,
        preconfig_type=preset_type,
        include=include,
        exclude=exclude,
        file_1=args.input[0],
        file_2=args.input[1],
        output=args.output,
        report_template=args.report_template,
        include_empty=args.include_empty
    )
    result, j1, j2 = compare_dicts(options)
    if preset_type == "bom":
        result, result_summary = perform_bom_diff(j1, j2)
    elif preset_type == "csaf":
        result, result_summary = perform_csaf_diff(j1, j2)
    else:
        result_summary = get_diff(j1, j2, options)
    report_results(result, result_summary, options, j1, j2)


if __name__ == "__main__":
    main()
