#!/usr/bin/env python3
"""Download vendored dependencies for offline builds.

Each component populates a subdirectory under <source-root>/vendor/.
Use ./configure --with-vendor to consume them at build time.
"""

import subprocess
import sys
from pathlib import Path

SRCDIR = Path(__file__).resolve().parent.parent
VENDOR_DIR = SRCDIR / "vendor"

COMPONENTS = {
    "package-manager": lambda: fetch_package_manager(),
}


def fetch_package_manager():
    dest = VENDOR_DIR / "package-manager"
    dest.mkdir(parents=True, exist_ok=True)
    pkg = SRCDIR / "auxil" / "package-manager"
    # Download the package and its runtime dependencies.
    subprocess.check_call(
        [sys.executable, "-m", "pip", "download", "-d", str(dest), str(pkg)]
    )
    # Also download build dependencies so `--no-index` builds work.
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib
    with open(pkg / "pyproject.toml", "rb") as f:
        build_requires = tomllib.load(f).get("build-system", {}).get("requires", [])
    if build_requires:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "download", "-d", str(dest), *build_requires]
        )


def main():
    if len(sys.argv) > 2 or (len(sys.argv) == 2 and sys.argv[1] not in COMPONENTS):
        print(f"Usage: {sys.argv[0]} [{'|'.join(COMPONENTS)}]", file=sys.stderr)
        raise SystemExit(1)

    targets = [sys.argv[1]] if len(sys.argv) == 2 else COMPONENTS
    for name in targets:
        COMPONENTS[name]()


if __name__ == "__main__":
    main()
