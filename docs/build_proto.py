"""Generate protobuf modules required by the legacy API documentation."""

import ast
import importlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROTO_DIR = ROOT / "ssh-cert-proto"
OUT_DIR = ROOT / "paramiko_cloud" / "protobuf"
BASE_MODULE = "paramiko_cloud.protobuf"


def run_protoc(*args: str) -> None:
    protoc = importlib.import_module("grpc_tools.protoc")
    protoc_main = getattr(protoc, "main", None)
    if not callable(protoc_main):
        raise TypeError("grpc_tools.protoc does not provide a compatible main function")
    result = protoc_main(["grpc_tools.protoc", *args])
    if not isinstance(result, int):
        raise TypeError("grpc_tools.protoc returned an invalid result")
    if result:
        raise SystemExit(result)


def rewrite_pb2_imports() -> None:
    for path in OUT_DIR.glob("*_pb2*.py"):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        lines = source.splitlines()
        replacements: list[tuple[int, int, list[str]]] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Import):
                continue
            if not node.names or not all(
                "." not in alias.name and alias.name.endswith("_pb2")
                for alias in node.names
            ):
                continue
            replacements.append(
                (
                    node.lineno - 1,
                    node.end_lineno or node.lineno,
                    [
                        f"from {BASE_MODULE} import {alias.name}"
                        + (f" as {alias.asname}" if alias.asname else "")
                        for alias in node.names
                    ],
                )
            )
        for start, end, replacement in sorted(replacements, reverse=True):
            lines[start:end] = replacement
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    proto_files = sorted(PROTO_DIR.glob("*.proto"))
    run_protoc(
        f"-I{PROTO_DIR}",
        f"--python_out={OUT_DIR}",
        *[str(proto_file) for proto_file in proto_files],
    )
    run_protoc(
        f"-I{PROTO_DIR}",
        f"--grpc_python_out={OUT_DIR}",
        str(PROTO_DIR / "rpc.proto"),
    )
    rewrite_pb2_imports()


if __name__ == "__main__":
    main()
