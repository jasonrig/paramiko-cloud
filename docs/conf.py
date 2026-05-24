# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


# -- Project information -----------------------------------------------------

project = "Paramiko-Cloud"
copyright = "2021, Jason Rigby"
author = "Jason Rigby"


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
]

autoclass_content = "both"
autodoc_class_signature = "separated"
autodoc_member_order = "bysource"
autodoc_typehints = "description"
autodoc_mock_imports = []

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "alabaster"

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = []


def _build_protobuf_sources() -> None:
    """Generate protobuf modules when the proto submodule is available."""

    proto_dir = ROOT / "ssh-cert-proto"
    generated_files = list((ROOT / "paramiko_cloud" / "protobuf").glob("*_pb2*.py"))
    if list(proto_dir.glob("*.proto")):
        subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "build_proto.py")],
            cwd=ROOT,
            check=True,
        )
    elif not generated_files:
        # Local checkouts may not have initialized the proto submodule yet.
        # Mock generated modules so prose-only docs and API pages still build.
        autodoc_mock_imports.extend(
            [
                "paramiko_cloud.protobuf.csr_pb2",
                "paramiko_cloud.protobuf.rpc_pb2",
                "paramiko_cloud.protobuf.rpc_pb2_grpc",
            ]
        )


_build_protobuf_sources()
