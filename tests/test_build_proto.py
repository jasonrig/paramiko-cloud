import tempfile
from pathlib import Path
from unittest import TestCase

from scripts.build_proto import validate_generated_module_path


class TestGeneratedModulePaths(TestCase):
    def test_accepts_generated_module_in_output_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "protobuf"
            output_dir.mkdir()
            generated_module = output_dir / "csr_pb2.py"
            generated_module.touch()

            self.assertEqual(
                validate_generated_module_path(generated_module, output_dir),
                generated_module.resolve(),
            )

    def test_rejects_generated_module_symlink_outside_output_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_dir = root / "protobuf"
            output_dir.mkdir()
            external_module = root / "external_pb2.py"
            external_module.touch()
            generated_module = output_dir / "csr_pb2.py"
            generated_module.symlink_to(external_module)

            with self.assertRaisesRegex(
                ValueError, "Generated module is outside the output directory"
            ):
                validate_generated_module_path(generated_module, output_dir)
