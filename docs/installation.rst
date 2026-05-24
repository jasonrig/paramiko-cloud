Installation
============

Paramiko-Cloud requires Python 3.10 or newer. Install the core package plus the
extra for each cloud provider you plan to use.

.. code-block:: bash

   python -m pip install "paramiko-cloud[aws]"
   python -m pip install "paramiko-cloud[gcp]"
   python -m pip install "paramiko-cloud[azure]"

Install all provider dependencies when you need more than one backend:

.. code-block:: bash

   python -m pip install "paramiko-cloud[all]"

Provider Dependencies
---------------------

The extras install the SDK used by each key wrapper:

.. list-table::
   :header-rows: 1

   * - Extra
     - Provider SDK
     - Key class
   * - ``aws``
     - ``boto3``
     - ``paramiko_cloud.aws.keys.ECDSAKey``
   * - ``gcp``
     - ``google-cloud-kms``
     - ``paramiko_cloud.gcp.keys.ECDSAKey``
   * - ``azure``
     - ``azure-keyvault-keys`` and ``azure-identity``
     - ``paramiko_cloud.azure.keys.ECDSAKey``

Development Setup
-----------------

The repository uses ``uv`` for local workflows:

.. code-block:: bash

   git submodule update --init --recursive
   uv sync --extra all --group dev --group docs
   uv run python scripts/build_proto.py

Generated protobuf modules are required before running type checks, tests, or
building the API reference. The proto definitions live in the ``ssh-cert-proto``
submodule and generated Python files are written to ``paramiko_cloud/protobuf``.

Build the documentation locally with:

.. code-block:: bash

   uv run sphinx-build -b html docs docs/_build/html

The project checks source code with:

.. code-block:: bash

   uv run ruff check .
   uv run ruff format . --check
   uv run mypy paramiko_cloud
   uv run pytest --cov=./ --cov-report=xml
