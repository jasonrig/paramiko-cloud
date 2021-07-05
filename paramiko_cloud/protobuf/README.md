# Where are the source files?

This directory contains generated protobuf Python source files, which are
not version controlled. To build these files, run:

```shell
# Generate the protobuf classes
python setup.py generate_py_protobufs

# Generate the gRPC stubs
python setup.py build_grpc
```