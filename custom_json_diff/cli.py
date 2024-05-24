import argparse

from custom_json_diff.custom_diff import (
    compare_dicts,
    get_common,
    get_diffs,
    perform_bom_diff,
    report_results
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
    # parser.add_argument(
    #     "--common",
    #      action="store_true",
    #      help="Include common elements as well as differences",
    #      dest="common",
    # )
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
    result, j1, j2 = compare_dicts(args.input[0], args.input[1], args.preset, args.exclude, args.config)
    diffs = get_diffs(args.input[0], args.input[1], j1, j2)
    if args.bom_diff:
        common = get_common(j1, j2)
        perform_bom_diff(result, diffs, common, args.input[0], args.input[1], args.output)
    else:
        report_results(result, diffs, args.output)


if __name__ == "__main__":
    main()
