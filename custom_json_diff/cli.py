import argparse

from custom_json_diff.custom_diff import (
    compare_dicts, get_diff, perform_bom_diff, report_results
)


def build_args():
    parser = argparse.ArgumentParser()
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
    parser.add_argument(
        "-a",
        "--allow-new-versions",
        action="store_true",
        help="Allow new versions in BOM comparison.",
        dest="allow_new_versions",
    )
    parser.add_argument(
        "-b",
        "--bom-diff",
         action="store_true",
         help="Produce a comparison of CycloneDX BOMs.",
         dest="bom_diff",
    )
    arg_group = parser.add_mutually_exclusive_group(required=True)
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
        help="Preset to use",
        choices=["cdxgen", "cdxgen-extended"],
        dest="preset",
    )
    return parser.parse_args()


def main():
    args = build_args()
    settings = args.preset or args.config or args.exclude
    result, j1, j2 = compare_dicts(args.input[0], args.input[1], settings, args.bom_diff, args.allow_new_versions)

    if args.bom_diff:
        result_summary = perform_bom_diff(j1, j2)
    else:
        result_summary = get_diff(args.input[0], args.input[1], j1, j2)
    report_results(result, result_summary, args.output, args.bom_diff, j1.filename, j2.filename)


if __name__ == "__main__":
    main()
