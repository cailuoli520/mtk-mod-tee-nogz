"""Public packaging and documentation checks; no private inputs."""
import hashlib
import importlib.util
import re
from pathlib import Path
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("nogz_package", ROOT / "scripts/package.py")
packager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(packager)


class RepositoryTests(unittest.TestCase):
    def test_public_files_have_no_private_paths_or_firmware(self):
        forbidden_suffixes = {".img", ".bin", ".elf", ".pem", ".key", ".log", ".pyc"}
        for name, path in packager.public_files():
            with self.subTest(file=name):
                self.assertNotIn("__pycache__", path.parts)
                self.assertNotIn("local-records.md", path.parts)
                self.assertNotIn(path.suffix.lower(), forbidden_suffixes)
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(re.search(r"[A-Za-z]:[\\/](?:Users|tmp)[\\/]", text))
                self.assertIsNone(re.search(r"/(?:home|mnt/[a-z]/Users)/[A-Za-z0-9_-]+", text))
                self.assertIsNone(re.search(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----", text))

    def test_markdown_local_links_and_anchors(self):
        for name, path in packager.public_files():
            if path.suffix != ".md":
                continue
            text = path.read_text(encoding="utf-8")
            for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", text):
                if target.startswith(("https://", "http://")):
                    continue
                relative, _, fragment = target.partition("#")
                destination = (path.parent / relative).resolve() if relative else path
                self.assertTrue(destination.is_relative_to(ROOT), (name, target))
                self.assertTrue(destination.is_file(), (name, target))
                if fragment:
                    body = destination.read_text(encoding="utf-8")
                    self.assertIn(f'<a id="{fragment}"></a>', body, (name, target))

    def test_archives_contain_exact_allowlists_and_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            archives = packager.package(output)
            for archive_path, source in zip(archives, (True, False)):
                expected = {f"mtk-tee-nogz/{name}": path.read_bytes()
                            for name, path in packager.public_files(source=source)}
                with zipfile.ZipFile(archive_path) as archive:
                    self.assertEqual(set(archive.namelist()), set(expected))
                    for name, data in expected.items():
                        self.assertEqual(archive.read(name), data)
            checksums = (output / "SHA256SUMS").read_text(encoding="ascii")
            for archive_path in archives:
                digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
                self.assertIn(f"{digest}  {archive_path.name}", checksums)

    def test_packaging_is_reproducible(self):
        with tempfile.TemporaryDirectory() as directory:
            a = packager.package(Path(directory) / "first")
            b = packager.package(Path(directory) / "second")
            self.assertEqual([p.read_bytes() for p in a], [p.read_bytes() for p in b])

    def test_existing_archives_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = root / "mtk-tee-nogz-source.zip"
            old.write_bytes(b"keep existing output")
            with self.assertRaisesRegex(ValueError, "overwrite"):
                packager.package(root)
            self.assertEqual(old.read_bytes(), b"keep existing output")
            self.assertFalse((root / "mtk-tee-nogz-skill.zip").exists())


if __name__ == "__main__":
    unittest.main()
