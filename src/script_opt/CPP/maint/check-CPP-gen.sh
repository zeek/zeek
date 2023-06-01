#! /bin/sh

abbr=$(echo $1 | sed 's,\.\./,,;s,/,#,g')
out=CPP-test/out.$abbr
gen_out=CPP-test/gen.$abbr

(
    /bin/echo -n $1" "
    if ! src/zeek -O gen-C++ --optimize-files=testing/btest $1 >&$gen_out 2>&1; then
        echo "fail"
        exit 1
    fi
    if grep -E -q '(deprecated.*(when|vector))|skipping|cannot be compiled|cannot compile|no matching functions' $gen_out; then
        echo "fail"
        exit 1
    fi
    echo "success"
    exit 0
) >$out 2>&1
