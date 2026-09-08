#! /usr/bin/env bash
set -e

DIFF_BASE=${DIFF_BASE:-origin/master}
DIFF_HEAD=${DIFF_HEAD:-HEAD}
BUILD_DIR=${BUILD_DIR:-./build}
CPUS=${ZEEK_CI_CPUS:-$(nproc)}

CLANG_TIDY_DIFF=${CLANG_TIDY_DIFF:-$(which clang-tidy-diff.py)}

if [ -z "${CLANG_TIDY_DIFF}" ]; then
    echo "missing clang-tidy-diff.py" >&2
    exit 1
fi

exec git diff -U0 "${DIFF_BASE}"..."${DIFF_HEAD}" | "$CLANG_TIDY_DIFF" -j "${CPUS}" -p 1 -path "${BUILD_DIR}"
