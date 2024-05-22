import argparse
import json

from custom_json_diff.custom_diff import (
    export_results, compare_dicts, get_diffs
)


def build_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i",
        "--input",
        action="store",
        help="Two JSON files to compare",
        required=True,
        nargs=2,
        dest="input",
    )
    parser.add_argument(
        "-o",
        "--output",
        action="store",
        help="Export JSON of differences to this file",
        dest="output",
    )
    arg_group = parser.add_mutually_exclusive_group(required=True)
    arg_group.add_argument(
        "-c",
        "--config-file",
        action="store",
        help="Import TOML configuration file",
        dest="config"
    )
    arg_group.add_argument(
        "-x",
        "--exclude",
        action="store",
        help="Exclude field(s) from comparison",
        default=[],
        dest="exclude",
        nargs="+",
    )
    arg_group.add_argument(
        "-p",
        "--preset",
        action="store",
        help="Preset to use",
        choices=["cdxgen", "cdxgen-minimal"],
        dest="preset",
    )
    return parser.parse_args()


def main():
    args = build_args()
    result, j1, j2 = compare_dicts(args.input[0], args.input[1], args.preset, args.exclude, args.config)
    if result == 0:
        print("Files are identical.")
    else:
        diffs = get_diffs(args.input[0], args.input[1], j1, j2)
        if args.output:
            export_results(args.output, diffs)
        else:
            print(json.dumps(diffs, indent=2))


if __name__ == "__main__":
    main()
