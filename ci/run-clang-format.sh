#! /bin/sh
#
# Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

base=$(git rev-parse --show-toplevel)
fix=0
pre_commit_hook=0

# Directories to run on by default. When changing, adapt .pre-commit-config.yam
# as well.
files="src"

error() {
    test "${pre_commit_hook}" = 0 && echo "$@" >&2 && exit 1
    exit 0
}

if [ $# != 0 ]; then
    case "$1" in
        --fixit)
            shift
            fix=1
            ;;

        --pre-commit-hook)
            shift
            fix=1
            pre_commit_hook=1
            ;;

        -*)
            echo "usage: $(basename $0) [--fixit | --pre-commit-hook] [<files>]"
            exit 1
    esac
fi

test $# != 0 && files="$@"

if [ -z "${CLANG_FORMAT}" ]; then
    CLANG_FORMAT=$(which clang-format 2>/dev/null)
fi

if [ -z "${CLANG_FORMAT}" -o ! -x "${CLANG_FORMAT}" ]; then
    error "Cannot find clang-format. If not in PATH, set CLANG_FORMAT."
fi

if ! (cd / && ${CLANG_FORMAT} -dump-config | grep -q SpacesInConditionalStatement); then
    error "${CLANG_FORMAT} does not support SpacesInConditionalStatement. Install custom version and put it into PATH, or point CLANG_FORMAT to it."
fi

if [ ! -e .clang-format ]; then
    error "Must execute in top-level directory."
fi

cmd="${base}/auxil/run-clang-format/run-clang-format.py -r --clang-format-executable ${CLANG_FORMAT} --exclude '*/3rdparty/*' ${files}"
tmp=/tmp/$(basename $0).$$.tmp
trap "rm -f ${tmp}" EXIT
eval "${cmd}" >"${tmp}"

if [ "${fix}" = 1 ]; then
    test -s "${tmp}" && cat "${tmp}" | git apply -p0
    true
else
    cat "${tmp}"
fi
