# custom-json-diff

Comparing two JSON files presents an issue when the two files have certain fields which are 
dynamically generated (e.g. timestamps), variable ordering, or other field which need to be 
excluded for one reason or another. Enter custom-json-diff, which allows you to specify fields to 
ignore in the comparison and sorts all fields.



## Installation
`pip install custom-json-diff`

## CLI Usage
```
usage: cjd [-h] -i INPUT INPUT (-c CONFIG_FILE | -x EXCLUDE [EXCLUDE ...] | -p {cdxgen})

options:
  -h, --help            show this help message and exit
  -i INPUT INPUT, --input INPUT INPUT
                        Two JSON files to compare
  -c CONFIG_FILE, --config-file CONFIG_FILE
                        Import TOML configuration file
  -x EXCLUDE [EXCLUDE ...], --exclude EXCLUDE [EXCLUDE ...]
                        Exclude field(s) from comparison
  -p {cdxgen}, --preset {cdxgen}
                        Preset to use

```

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
objects, you would specify `field1.field3.[].a`. custom-json-diff will create a regex which will 
account for the array index in the field name. Multiple fields may be specified separated by a 
space. To better understand what your fields should be, check out json-flatten, which is the 
package used for this function.

## Sorting

custom-json-diff will sort the imported JSON alphabetically. If your JSON document contains arrays 
of objects, you will need to specify any keys you want to sort by in a toml file or use a preset.
The first key located from the provided keys that is present in the object will be used for sorting.

## TOML config file example

```toml
[settings]
excluded_fields = ["serialNumber", "metadata.timestamp"]
sort_keys = ["url", "content", "ref", "name", "value"]
```