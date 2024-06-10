# custom-json-diff

Comparing two JSON files presents an issue when the two files have certain fields which are 
dynamically generated (e.g. timestamps), variable ordering, or other fields which need to be 
excluded for one reason or another. Enter custom-json-diff, which allows you to specify fields to 
ignore in the comparison and sorts all fields.



## Installation
`pip install custom-json-diff`

## CLI Usage

Note, you may use `cjd` rather than `custom-json-diff` to run.

```
usage: custom-json-diff [-h] [-v] -i INPUT INPUT [-o OUTPUT] [-c CONFIG] [-x EXCLUDE] [--debug] {bom-diff} ...

positional arguments:
  {bom-diff}            subcommand help
    bom-diff            compare CycloneDX BOMs

options:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -i INPUT INPUT, --input INPUT INPUT
                        Two JSON files to compare - older file first.
  -o OUTPUT, --output OUTPUT
                        Export JSON of differences to this file.
  -c CONFIG, --config-file CONFIG
                        Import TOML configuration file (overrides commandline options).
  -x EXCLUDE, --exclude EXCLUDE
                        Exclude field(s) from comparison.
  --debug               Print debug messages.

```

bom-diff usage
```
usage: custom-json-diff bom-diff [-h] [--allow-new-versions] [--allow-new-data] [--components-only] [-r REPORT_TEMPLATE] [--include-extra INCLUDE]

options:
  -h, --help            show this help message and exit
  --allow-new-versions, -anv
                        Allow newer versions in second BOM to pass.
  --allow-new-data, -and
                        Allow populated values in newer BOM to pass against empty values in original BOM.
  --components-only     Only compare components.
  -r REPORT_TEMPLATE, --report-template REPORT_TEMPLATE
                        Jinja2 template to use for report generation.
  --include-extra INCLUDE
                        Include properties/evidence/licenses/hashes/externalReferences (list which with comma, no space, inbetween).
```

## Bom Diff

The bom-diff command compares CycloneDx BOM components, services, and dependencies, as well as data 
outside of these parts. 

Some fields are excluded from the component comparison by default but can be explicitly specified 
for inclusion using `bom-diff --include-extra` and whichever field(s) you wish to include (e.g. 
`--include-extra properties,evidence,licenses`:
- properties
- evidence
- licenses
- hashes
- externalReferences

You can use the -x --exclude switch before the bom-diff command to exclude any of these 
(see [Specifying fields to exclude](#specifying-fields-to-exclude) ).

Default included fields:

components:
- author
- bom-ref
- description
- group
- name
- publisher
- purl
- scope
- type
- version

services
- name
- endpoints
- authenticated
- x-trust-boundary

dependencies
- ref
- dependsOn

The --allow-new-versions option attempts to parse component versions and ascertain if a discrepancy 
is attributable to an updated version. Dependency refs and dependents are compared with the version 
string removed rather than checking for a newer version.

The --allow-new-data option allows for empty fields in the original BOM not to be reported as a 
difference when the data is populated in the second specified BOM. It also addresses when a field 
such as properties is expanded, checking that all original elements are still present but allowing
additional elements in the newer BOM.

The --components-only option only analyzes components, not services, dependencies, or other data.

## Specifying fields to exclude

To exclude fields from comparison, use the `-x` or `--exclude` flag and specify the field name(s) 
to exclude. The json will be flattened, so fields are specified using dot notation. For example:

```json
{
    "field1": {
        "field2": "value", 
        "field3": [
            {"a": "val1", "b": "val2"}, 
            {"a": "val3", "b": "val4"}
        ]
    }
}
```

is flattened to:
```json
{
    "field1.field2": "value",
    "field1.field3.[0].a": "val1",
    "field1.field3.[0].b": "val2",
    "field1.field3.[1].a": "val3",
    "field1.field3.[1].b": "val4"
}
```

To exclude field2, you would specify `field1.field2`. To exclude the `a` field in the array of 
objects, you would specify `field1.field3.[].a` (do NOT include the array index, just do `[]`). 
Multiple fields may be specified separated by a comma (no space). To better understand what your fields should
be, check out json-flatten, which is the package used for this function.

## Sorting

custom-json-diff will sort the imported JSON alphabetically. If your JSON document contains arrays 
of objects, you will need to specify any keys you want to sort by in a toml file or use a preset.
The first key located from the provided keys that is present in the object will be used for sorting.

## TOML config file example

```toml
[settings]
excluded_fields = []
sort_keys = ["url", "content", "ref", "name", "value"]

[bom_settings]
allow_new_data = false
allow_new_versions = true
components_only = false
include_extra = ["licenses", "properties", "hashes", "evidence", "externalReferences"]
report_template = "custom_json_diff/bom_diff_template.j2"
```