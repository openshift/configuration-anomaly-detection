# Contribution Guide

## build and test
to build the code you can use the
```shell
make
```
target.

## verify error messages are unique
in order to grep any part of an error message and see the exact location is was created in, use the following command:
```shell
grep -Ir  'fmt.Errorf("' . | grep -v ./CONTRIBUTING.md | sed 's/\(.*\)\(fmt.Errorf.*\)/\2/'  | sort
```
and verify there are no two entries with the same string

this also forces us to use `fmt.Errorf` and not a `errors.New`

## Other
additional steps will be added as required
