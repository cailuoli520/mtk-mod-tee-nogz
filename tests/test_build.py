"""Synthetic tests only: no vendor firmware, pwnage or devices required."""
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("nogz_build", ROOT / "scripts/build.py")
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)


def container_part(name, payload, header_size=512, alignment=16):
    header = bytearray(512)
    struct.pack_into("<II", header, 0, 0x58881688, len(payload))
    encoded = name.encode("ascii")
    header[8:8 + len(encoded)] = encoded
    struct.pack_into("<I", header, 52, header_size)
    struct.pack_into("<I", header, 68, alignment)
    return bytes(header) + payload + bytes((-len(payload)) % 16)


def synthetic_atf(profile):
    data = bytearray(0x70000)
    for offset, before, _ in build.patches(profile):
        struct.pack_into("<I", data, offset, before)
    # These unchanged callback instructions update the ATF flags global.
    callback, flag = profile["callback"], profile["flag"]
    page_delta = ((build.A + flag) >> 12) - ((build.A + callback + 4) >> 12)
    page_delta &= (1 << 21) - 1
    adrp = 0x90000009 | ((page_delta & 3) << 29) | ((page_delta >> 2) << 5)
    store = 0xB9000000 | (((flag & 0xFFF) // 4) << 10) | (9 << 5) | 8
    struct.pack_into("<I", data, callback + 4, adrp)
    struct.pack_into("<I", data, callback + 12, store)
    return bytes(data)


class ContainerTests(unittest.TestCase):
    def test_parse_aligned_groups_and_certificates(self):
        data = (container_part("atf", b"ATF")
                + container_part("cert1", b"synthetic-certificate")
                + container_part("cert2", b"synthetic-certificate")
                + container_part("tee", b"TEE"))
        self.assertEqual(build.parts(data), {"atf": b"ATF", "tee": b"TEE"})

    def test_duplicate_group_rejected(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            build.parts(container_part("atf", b"a") + container_part("atf", b"b"))

    def test_truncated_payload_rejected(self):
        with self.assertRaisesRegex(ValueError, "Truncated"):
            build.parts(container_part("atf", b"x" * 32)[:-17])

    def test_unknown_header_size_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            build.parts(container_part("atf", b"x", header_size=256))

    def test_unknown_alignment_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            build.parts(container_part("atf", b"x", alignment=32))


class PatchTests(unittest.TestCase):
    def test_scope_length_and_original_unchanged(self):
        for name in ("yunluo", "peral", "xaga"):
            with self.subTest(profile=name):
                p = build.load_profile(name)
                original = synthetic_atf(p)
                saved = bytes(original)
                result = build.patch(original, p)
                expected = {o + i for o, _, _ in build.patches(p) for i in range(4)}
                changed = {i for i, (a, b) in enumerate(zip(original, result)) if a != b}
                self.assertEqual(len(result), len(original))
                self.assertEqual(original, saved)
                self.assertTrue(changed <= expected)
                self.assertEqual(len(build.patches(p)), 10)

    def test_wrong_original_instruction_rejected(self):
        p = build.load_profile("peral")
        data = bytearray(synthetic_atf(p))
        data[p["pc_patch"]] ^= 1
        with self.assertRaisesRegex(ValueError, "Original instruction mismatch"):
            build.patch(data, p)

    def test_whole_image_offset_matches_payload_patch(self):
        p = build.load_profile("yunluo")
        data = synthetic_atf(p)
        image = container_part("atf", data)
        patched = build.patch(image, p, 512)
        self.assertEqual(patched[:512], image[:512])
        self.assertEqual(build.parts(patched)["atf"], build.patch(data, p))

    def test_pc_opcode_independently_decodes(self):
        p = build.load_profile("peral")
        data = build.patch(synthetic_atf(p), p)
        off = p["pc_patch"]
        instruction = next(build.MD.disasm(data[off:off + 4], build.A + off))
        self.assertEqual(instruction.op_str, "x8, #0x50f00000")
        wrong = next(build.MD.disasm(struct.pack("<I", 0xD2A21E08), build.A + off))
        self.assertEqual(wrong.op_str, "x8, #0x10f00000")

    def test_branch_encoding_and_limits(self):
        word = build.branch(0x1000, 0x800)
        instruction = next(build.MD.disasm(struct.pack("<I", word), 0x1000))
        self.assertEqual(instruction.op_str, "#0x800")
        for dst in (1, 1 << 27, -(1 << 27) - 4):
            with self.subTest(destination=dst):
                with self.assertRaises(ValueError):
                    build.branch(0, dst)


class SyntheticExecutionTests(unittest.TestCase):
    def test_getter_does_not_clean_arbitrary_x0(self):
        for name in ("yunluo", "peral", "xaga"):
            p = build.load_profile(name)
            data = build.patch(synthetic_atf(p), p)
            m = build.Machine(data, b"", p)
            start = build.A + p["getter"]
            self.assertEqual(m.run(start, [(start, start + 20)], (0xBADF00D,)), build.STOP)
            self.assertEqual(m.x(0), 0)
            self.assertEqual(m.events, [])

    def test_callback_synchronizes_and_preserves_abi(self):
        for name in ("yunluo", "peral", "xaga"):
            with self.subTest(profile=name):
                p = build.load_profile(name)
                data = build.patch(synthetic_atf(p), p)
                m = build.Machine(data, b"", p)
                pointer = build.TAG + 8
                m.word(pointer, 0)
                for register in range(19, 30):
                    m.x(register, 0xABCD0000 + register)
                c, g = build.A + p["callback"], build.A + p["getter"]
                m.run(c, [(c, c + 20), (g, g + 20)], (pointer,))
                self.assertEqual(m.word(pointer), 1)
                self.assertEqual(m.word(build.A + p["flag"]), 1)
                self.assertEqual(m.x(0), 0)
                self.assertEqual(m.x(30), build.STOP)
                self.assertEqual([m.x(i) for i in range(19, 30)],
                                 [0xABCD0000 + i for i in range(19, 30)])
                self.assertLess(m.events.index(("dc_cvac", pointer, 1)),
                                m.events.index(("dsb_sy",)))

    def test_aliases_share_storage(self):
        p = build.load_profile("peral")
        m = build.Machine(synthetic_atf(p), b"", p)
        m.word(build.TAG, 0x1234)
        self.assertEqual(m.word(build.HIGH | build.TAG), 0x1234)
        m.word(build.HIGH | build.TAG, 0x5678)
        self.assertEqual(m.word(build.TAG), 0x5678)

    def test_budget_exhaustion_rejected(self):
        p = build.load_profile("peral")
        m = build.Machine(struct.pack("<I", 0x14000000), b"", p)
        with self.assertRaisesRegex(ValueError, "budget"):
            m.run(build.A, [(build.A, build.A + 4)], budget=2)

    def test_instruction_outside_whitelist_rejected(self):
        p = build.load_profile("peral")
        m = build.Machine(struct.pack("<I", 0xD65F03C0), b"", p)
        with self.assertRaisesRegex(ValueError, "Unmodelled PC"):
            m.run(build.A, [])


class CommandTests(unittest.TestCase):
    def test_unknown_input_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tee, lk, output = root / "tee.img", root / "lk.img", root / "result"
            tee.write_bytes(container_part("atf", b"synthetic"))
            lk.write_bytes(container_part("lk", b"synthetic"))
            before = tee.read_bytes()
            result = subprocess.run(
                [sys.executable, "-B", str(ROOT / "scripts/build.py"), "--profile", "peral",
                 "--tee", str(tee), "--lk", str(lk), "--out-dir", str(output)],
                capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Unknown tee SHA256", result.stderr)
            self.assertFalse(output.exists())
            self.assertEqual(tee.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
