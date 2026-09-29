"""Detector preservation, refusal paths, and signing-command orchestration."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_build import ROOT, build, container_part, synthetic_atf

DETECTOR = ROOT / "scripts/detect_pl_cert_mode.py"


class DetectorTests(unittest.TestCase):
    def test_provided_detector_is_byte_identical(self):
        self.assertEqual(
            hashlib.sha256(DETECTOR.read_bytes()).hexdigest(),
            "a11f209e8cef3a08f43b39875386d345c00836c7f4c25f48712a58308fe041c7",
        )

    def test_unsupported_preloader_returns_manual_with_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, report = root / "preloader.bin", root / "report.txt"
            image.write_bytes(b"not a supported preloader")
            result = subprocess.run(
                [sys.executable, "-B", str(DETECTOR), str(image), "--json", "--report", str(report)],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 3, result.stderr)
            self.assertEqual(json.loads(result.stdout)["results"][0]["status"], "NEED_MANUAL")
            self.assertIn("NEED_MANUAL", report.read_text(encoding="utf-8"))
            self.assertEqual(image.read_bytes(), b"not a supported preloader")

    def test_detector_report_cannot_overwrite_input(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "preloader.bin"
            original = b"unsupported but must be preserved"
            image.write_bytes(original)
            result = subprocess.run(
                [sys.executable, "-B", str(DETECTOR), str(image), "--report", str(image)],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(image.read_bytes(), original)


class SigningModeTests(unittest.TestCase):
    def test_new_has_no_mode_flag(self):
        self.assertEqual(build.cert_mode_flags("NEW_PARSER"), [])

    def test_legacy_adds_only_legacy_flag(self):
        self.assertEqual(build.cert_mode_flags("LEGACY"), ["--legacy"])

    def test_ambiguous_or_unrecognized_result_is_rejected(self):
        for status in ("NEED_MANUAL", "UNKNOWN", "", None):
            with self.subTest(status=status):
                with self.assertRaisesRegex(ValueError, "not conclusive"):
                    build.cert_mode_flags(status)

    def test_orchestration_uses_detected_mode_not_profile(self):
        # Both modes deliberately use the same profile. Tool results are mocked
        # here to verify orchestration, not to claim cryptographic verification.
        for status, mode, flags in (
            ("NEW_PARSER", "new", []),
            ("LEGACY", "legacy", ["--legacy"]),
            ("NEED_MANUAL", None, None),
        ):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                p = build.load_profile("peral")
                tee, lk, pl = root / "tee.img", root / "lk.img", root / "preloader.bin"
                tee.write_bytes(container_part("atf", synthetic_atf(p)) + container_part("tee", b"TEE"))
                lk.write_bytes(container_part("lk", b"LK"))
                pl.write_bytes(b"synthetic detector input")
                p["tee_sha256"], p["lk_sha256"] = build.sha(tee.read_bytes()), build.sha(lk.read_bytes())
                tools, output = root / "tools", root / "output"
                tools.mkdir()
                for name in ("sign_mtk_cert.py", "verify_mtk_image.py"):
                    (tools / name).write_text("# test boundary\n", encoding="utf-8")
                calls = []

                def tool(_tools, name, args, _log):
                    calls.append((name, args))
                    if name == "detect_pl_cert_mode.py":
                        return json.dumps({"results": [{
                            "path": str(pl.resolve()), "sha256": build.sha(pl.read_bytes()),
                            "status": status, "isa": "test", "reason": "mocked orchestration input",
                        }]})
                    if name == "sign_mtk_cert.py":
                        Path(args[-1]).write_bytes(Path(args[0]).read_bytes())
                        return "mocked signing boundary"
                    return "Result: VALID\nResult: VALID\n"

                argv = [
                    "build.py", "--profile", "peral", "--tee", str(tee), "--lk", str(lk),
                    "--preloader", str(pl), "--tools", str(tools), "--out-dir", str(output),
                ]
                with patch.object(sys, "argv", argv), \
                     patch.object(build, "load_profile", return_value=p), \
                     patch.object(build, "regression", return_value=["orchestration-only"]), \
                     patch.object(build, "run_tool", side_effect=tool), \
                     contextlib.redirect_stdout(io.StringIO()):
                    if mode is None:
                        with self.assertRaisesRegex(ValueError, "not conclusive"):
                            build.main()
                    else:
                        build.main()
                if mode is None:
                    self.assertEqual([name for name, _ in calls], ["detect_pl_cert_mode.py"])
                    self.assertFalse((output / "tee.unsigned.img").exists())
                    self.assertFalse((output / "manifest.json").exists())
                else:
                    sign_args = next(args for name, args in calls if name == "sign_mtk_cert.py")
                    self.assertEqual(sign_args[1:-1], [*flags, "--all", "-w", "-o"])
                    self.assertNotIn("--new", sign_args)
                    self.assertEqual(Path(sign_args[-1]).name, f"tee_nogz_{mode}.img")
                    manifest = json.loads((output / "manifest.json").read_text())
                    self.assertEqual(manifest["cert_mode"], mode)
                    self.assertEqual(manifest["signing_mode_flags"], flags)
                    if mode == "new":
                        self.assertIsNone(manifest["historical_output_matches"])


if __name__ == "__main__":
    unittest.main()
