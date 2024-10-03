# custom-json-diff

Comparing two JSON files presents an issue when the two files have certain fields which are 
dynamically generated (e.g. timestamps), variable ordering, or other fields which need to be 
excluded or undergo specialized comparison for one reason or another. Enter custom-json-diff, 
which allows you to specify fields to ignore in the comparison and sorts all fields.


## Installation
`pip install custom-json-diff`

## CLI Usage

Note, you may use `cjd` rather than `custom-json-diff` to run.

```
usage: custom-json-diff [-h] [-v] -i INPUT INPUT [-o OUTPUT] [-c CONFIG] [-x EXCLUDE] [--debug] {preset-diff} ...

positional arguments:
  {preset-diff}         subcommand help
    preset-diff         Compare CycloneDX BOMs or Oasis CSAFs

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

preset-diff usage
```
usage: custom-json-diff preset-diff [-h] [--allow-new-versions] [--allow-new-data] [--type PRESET_TYPE] [-r REPORT_TEMPLATE] [--include-extra INCLUDE]

options:
  -h, --help            show this help message and exit
  --allow-new-versions, -anv
                        BOM only - allow newer versions in second BOM to pass.
  --allow-new-data, -and
                        Allow populated values in newer BOM or CSAF to pass against empty values in original BOM/CSAF.
  --type PRESET_TYPE    Either bom or csaf
  -r REPORT_TEMPLATE, --report-template REPORT_TEMPLATE
                        Jinja2 template to use for report generation.
  --include-extra INCLUDE
                        BOM only - include properties/evidence/licenses/hashes/externalReferences (list which with comma, no space, inbetween).

```
## Preset Diffs

CJD offers advanced diffing for Cyclonedx BOM (v1.5 or v1.6) produced by 
[CycloneDx Cdxgen](https://github.com/CycloneDX/cdxgen) and Oasis CSAF v2 produced by 
[OWASP-dep-scan](https://github.com/OWASP-dep-scan/dep-scan).


### Bom Diff

The `preset-diff --type bom` command compares CycloneDx BOM components, services, and dependencies, as well as data 
outside of these parts. 

Some component fields are excluded from the component comparison by default but can be explicitly 
specified for inclusion using `preset-diff --include-extra` and whichever field(s) you wish to include (e.g. 
`--include-extra properties,evidence,licenses`:
- properties
- evidence
- licenses
- hashes
- externalReferences

You can use the -x --exclude switch before the preset-diff command to exclude any of these 
(see [Specifying fields to exclude](#specifying-fields-to-exclude)) except for bom-ref, as that is needed for the comparison -
if the bom-ref includes a version, that part can be excluded as needed (see 
[Allowing newer versions](#allowing-newer-versions)).

Default included fields:

bomFormat
metadata
specVersion
version

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
- dependsOn
- ref

vulnerabilities
- advisories
- affects
- analysis
- bom-ref
- cwes
- description
- detail
- id
- properties
- published
- ratings
- recommendation
- references
- source
- updated


### CSAF Diff

CSAF diffing includes the following fields at this time. Only the vulnerabilities section uses the 
allows new data option. Fields can be excluded using the -x --exclude as described for bom diffing
except for title as that is currently being populated by depscan with the bom-ref of the 
vulnerability as a unique id.

document

product_tree

vulnerabilities
- acknowledgements
- cwe
- cve
- discovery_date
- ids
- notes
- product_status
- references
- scores
- title


### Allowing newer versions

[Currently BOM only] The --allow-new-versions option attempts to parse component versions and 
ascertain if a discrepancy is attributable to an updated version. Dependency refs and dependents 
are compared with the version string removed rather than checking for a newer version.


### Allowing new data

The --allow-new-data option allows for empty fields in the original BOM not to be reported as a 
difference when the data is populated in the second specified BOM. It also addresses when a field 
such as properties is expanded, checking that all original elements are still present but allowing
additional elements in the newer BOM.

The --components-only option only analyzes components, not services, dependencies, or other data.

### Report Template

You may use the builtin report templates or create one of your own. The variables available to you
for each preset type are as follows.

**BOM**
* common_lib
* common_frameworks
* common_services
* common_deps
* common_apps
* common_other
* common_vdrs
* diff_lib_1
* diff_lib_2
* diff_frameworks_1
* diff_frameworks_2
* diff_apps_1
* diff_apps_2
* diff_other_1
* diff_other_2
* diff_services_1
* diff_services_2
* diff_deps_1
* diff_deps_2
* diff_vdrs_1
* diff_vdrs_2
* bom_1 (filename)
* bom_2
* stats (this is a statistic summary)
* metadata (a bool to indicate if misc_data passed)
* diff_status (integer representing the diff status)

**CSAF**
* common_document
* common_product_tree
* common_vulnerabilities
* diff_document_1
* diff_document_2
* diff_product_tree_1
* diff_product_tree_2
* diff_vulnerabilities_1
* diff_vulnerabilities_2
* diff_status (integer representing the diff status)
* csaf_1 (filename)
* csaf_2


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
The first key located from the provided keys that is present in the object will be used, so order
any keys provided accordingly.

## TOML config file example

```toml
[settings]
excluded_fields = []
sort_keys = ["url", "content", "ref", "name", "value"]

[preset_settings]
type = "bom"
allow_new_data = false
allow_new_versions = true
components_only = false
include_extra = ["licenses", "properties", "hashes", "evidence", "externalReferences"]
report_template = "custom_json_diff/bom_diff_template.j2"
```