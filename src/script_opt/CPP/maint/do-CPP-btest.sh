#! /bin/sh

rm -f CPP-gen.cc
cp zeek.HOLD src/zeek || (
    echo Need to create clean zeek.HOLD
    exit 1
) || exit 1

base=$(echo $1 | sed 's,\.\./,,;s,/,#,g')
rel_test=$(echo $1 | sed 's,.*testing/btest/,,')

export ZEEK_GEN_CPP=1
export ZEEK_CPP_DIR=$(pwd)
# export ZEEK_OPT_FUNCS="<global-stmts>"
export ZEEK_OPT_FILES="testing/btest"

(
    cd ../testing/btest
    ../../auxil/btest/btest $rel_test
)

# export -n ZEEK_GEN_CPP ZEEK_CPP_DIR ZEEK_OPT_FUNCS ZEEK_OPT_FILES
export -n ZEEK_GEN_CPP ZEEK_CPP_DIR ZEEK_OPT_FILES

ninja

(
    cd ../testing/btest
    ../../auxil/btest/btest -a cpp -d -f ../../build/CPP-test/diag.$base $rel_test
)
