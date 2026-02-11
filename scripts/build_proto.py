#!/usr/bin/env python3
from glob import glob
from pathlib import Path
import re

import grpc_tools.protoc

ROOT = Path(__file__).resolve().parent.parent
PROTO_DIR = ROOT / "ssh-cert-proto"
OUT_DIR = ROOT / "paramiko_cloud" / "protobuf"
BASE_MODULE = "paramiko_cloud.protobuf"


def run_protoc(*args: str) -> None:
    rc = grpc_tools.protoc.main(["grpc_tools.protoc", *args])
    if rc != 0:
        raise SystemExit(rc)


def rewrite_pb2_imports() -> None:
    for proto_file in glob(str(OUT_DIR / "*_pb2*.py")):
        path = Path(proto_file)
        lines = path.read_text().splitlines()
        rewritten: list[str] = []

        for line in lines:
            match_alias = re.match(r"^import\s+([A-Za-z0-9_]+_pb2)\s+as\s+([A-Za-z0-9_]+)$", line)
            if match_alias:
                module_name, alias = match_alias.groups()
                rewritten.append(f"from {BASE_MODULE} import {module_name} as {alias}")
                continue

            match_plain = re.match(r"^import\s+([A-Za-z0-9_]+_pb2)$", line)
            if match_plain:
                module_name = match_plain.group(1)
                rewritten.append(f"from {BASE_MODULE} import {module_name}")
                continue

            rewritten.append(line)

        path.write_text("\n".join(rewritten) + "\n")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    proto_files = sorted(PROTO_DIR.glob("*.proto"))
    run_protoc(
        f"-I{PROTO_DIR}",
        f"--python_out={OUT_DIR}",
        *[str(p) for p in proto_files],
    )

    rpc_proto = PROTO_DIR / "rpc.proto"
    run_protoc(
        f"-I{PROTO_DIR}",
        f"--grpc_python_out={OUT_DIR}",
        str(rpc_proto),
    )

    rewrite_pb2_imports()


if __name__ == "__main__":
    main()
