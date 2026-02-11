# Where are the source files?

This directory contains generated protobuf Python source files, which are not version controlled. To build these files,
run:

```shell
# Generate the protobuf classes gRPC stubs
uv run python scripts/build_proto.py
```
