"""Package only explicitly approved public files; never include firmware."""
import argparse
import hashlib
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_FILES = (
    "README.md",
    "SKILL.md",
    "requirements.txt",
    "agents/openai.yaml",
    "docs/technical-guide.md",
    "references/adaptation.md",
    "references/profiles.json",
    "scripts/build.py",
)
DEVELOPMENT_FILES = (
    ".gitignore",
    ".gitattributes",
    ".github/workflows/ci.yml",
    "scripts/package.py",
    "tests/test_build.py",
    "tests/test_repository.py",
)


def public_files(root=ROOT, source=True):
    root = root.resolve()
    names = list(RUNTIME_FILES + (DEVELOPMENT_FILES if source else ()))
    if (root / "LICENSE").is_file():
        names.append("LICENSE")
    for name in sorted(names):
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"Missing or symlinked public file: {name}")
        if not path.resolve().is_relative_to(root):
            raise ValueError(f"Public file escapes repository: {name}")
        yield name, path


def write_archive(destination, files):
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, path in files:
            entry = zipfile.ZipInfo(f"mtk-tee-nogz/{name}", (1980, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, path.read_bytes())


def package(output, root=ROOT):
    plans = (
        ("mtk-tee-nogz-source.zip", list(public_files(root, source=True))),
        ("mtk-tee-nogz-skill.zip", list(public_files(root, source=False))),
    )
    for name in [name for name, _ in plans] + ["SHA256SUMS"]:
        if (output / name).exists():
            raise ValueError(f"Refusing to overwrite: {output / name}")
    output.mkdir(parents=True, exist_ok=True)
    hashes = []
    for name, files in plans:
        destination = output / name
        write_archive(destination, files)
        hashes.append(f"{hashlib.sha256(destination.read_bytes()).hexdigest()}  {name}\n")
    with (output / "SHA256SUMS").open("x", encoding="ascii", newline="\n") as stream:
        stream.writelines(hashes)
    return [output / name for name, _ in plans]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("dist"))
    args = parser.parse_args()
    for path in package(args.output):
        print(path.resolve())


if __name__ == "__main__":
    main()
