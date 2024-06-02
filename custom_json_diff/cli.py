import argparse

from custom_json_diff.custom_diff import (
    compare_dicts, get_diff, perform_bom_diff, report_results
)
from custom_json_diff.custom_diff_classes import Options


def build_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help="subcommand help")
    parser_bom_diff = subparsers.add_parser("bom-diff", help="compare CycloneDX BOMs")
    parser_bom_diff.set_defaults(bom_diff=True)
    parser_bom_diff.add_argument(
        "-a",
        "--allow-new-versions",
        action="store_true",
        help="Allow new versions in BOM comparison.",
        dest="allow_new_versions",
    )
    # parser_bom_diff.add_argument(
    #     "-r",
    #     "--report-template",
    #     action="store",
    #     help="Jinja2 template to use for report generation.",
    #     dest="report_template",
    # )
    parser.add_argument(
        "-i",
        "--input",
        action="store",
        help="Two JSON files to compare.",
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
    arg_group = parser.add_mutually_exclusive_group()
    arg_group.add_argument(
        "-c",
        "--config-file",
        action="store",
        help="Import TOML configuration file.",
        dest="config"
    )
    arg_group.add_argument(
        "-x",
        "--exclude",
        action="store",
        help="Exclude field(s) from comparison.",
        default=[],
        dest="exclude",
        nargs="+",
    )
    arg_group.add_argument(
        "-p",
        "--preset",
        action="store",
        help="Preset to use.",
        choices=["cdxgen", "cdxgen-extended"],
        dest="preset",
    )
    return parser.parse_args()


def main():
    args = build_args()
    options = Options(
        allow_new_versions=args.allow_new_versions,
        bom_diff=args.bom_diff,
        config=args.config,
        exclude=args.exclude,
        file_1=args.input[0],
        file_2=args.input[1],
        output=args.output,
        preset=args.preset,
        report_template=args.report_template,
        sort_keys=[],
    )
    result, j1, j2 = compare_dicts(options)

    if args.bom_diff:
        result_summary = perform_bom_diff(j1, j2, options)
    else:
        result_summary = get_diff(j1, j2, options)
    report_results(result, result_summary, options)


if __name__ == "__main__":
    main()
