# custom-json-diff

Comparing two JSON files presents an issue when the two files have certain fields which are 
dynamically generated (e.g. timestamps), variable ordering, or other field which need to be 
excluded for one reason or another. Enter custom-json-diff, which allows you to specify fields to 
ignore in the comparison and sorts all fields.

## Installation
`pip install custom-json-diff`

## CLI Usage
```
usage: cjd [-h] [-x EXCLUDE] [-p {cdxgen}] -i INPUT INPUT [-r]

options:
  -h, --help            show this help message and exit
  -x EXCLUDE, --exclude EXCLUDE
                        exclude field(s) from comparison
  -p {cdxgen}, --preset {cdxgen}
                        preset to use
  -i INPUT INPUT, --input INPUT INPUT
                        Two input files to compare
  -r, --regex           Excluded keys are regular expressions.

```

## Specifying fields to exclude

To exclude fields from comparison, use the `-x` or `--exclude` flag and specify the field name(s) 
to exclude. The json will be flattened, so fields are specified using dot notation. For example:

```
{
    field1: {
        field2: value, 
        field3: [
            {a: val1, b: val2}, 
            {a: val3, b: val4}
        ]
    }
}
```

To exclude field2, you would specify `field1.field2`. To exclude the `a` field in the array, you 
would specify `field1.field3[\d+].a` and use the -r/--regex flag. Specify multiple fields with a 
space. To better understand what your fields should be, check out json-flatten, which is the 
package used for this function.