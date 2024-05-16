import argparse
import json

from custom_json_diff.custom_diff import import_toml, set_excluded_fields, compare_dicts, get_diffs


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
    arg_group = parser.add_mutually_exclusive_group(required=True)
    arg_group.add_argument(
        "-c",
        "--config-file",
        action="store",
        help="Import TOML configuration file",
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
    # parser.add_argument(
    #     "-s",
    #     "--skip-filepaths",
    #     action="store_true",
    #     help="skip filepaths in comparison",
    #     default=False,
    #     dest="skip_filepaths",
    #     )
    arg_group.add_argument(
        "-p",
        "--preset",
        action="store",
        help="Preset to use",
        choices=["cdxgen"],
        dest="preset",
    )
    return parser.parse_args()


def main():
    args = build_args()
    if args.preset:
        exclude_keys, sort_keys = set_excluded_fields(args.preset)
    elif args.config_file:
        exclude_keys, sort_keys = import_toml(args.config_file)
    else:
        exclude_keys = set(args.exclude)
        sort_keys = []
    result, j1, j2 = compare_dicts(args.input[0], args.input[1], exclude_keys, sort_keys)
    if result == 0:
        print("Files are identical")
    else:
        diffs = get_diffs(args.input[0], args.input[1], j1, j2)
        print(json.dumps(diffs, indent=2))


if __name__ == "__main__":
    main()
