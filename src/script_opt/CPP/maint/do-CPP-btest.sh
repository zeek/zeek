#! /bin/sh

rm -f CPP-gen.cc src/zeek

cp zeek.HOLD src/zeek || (
    echo Need to create clean zeek.HOLD
    exit 1
) || exit 1

if [ "$1" == "-U" ]; then
    btest_opt=-U
    shift
elif [ "$1" == "-d" ]; then
    btest_opt=-d
    shift
else
    btest_opt=-d
fi

base=$(echo $1 | sed 's,\.\./,,;s,/,#,g')
rel_test=$(echo $1 | sed 's,.*testing/btest/,,')

export ZEEK_GEN_CPP=1
export ZEEK_REPORT_UNCOMPILABLE=1
export ZEEK_CPP_DIR=$(pwd)
# export ZEEK_OPT_FUNCS="<global-stmts>"
export ZEEK_OPT_FILES="testing/btest"

(
    cd ../testing/btest
    ../../auxil/btest/btest $rel_test
)

# export -n ZEEK_GEN_CPP ZEEK_CPP_DIR ZEEK_OPT_FUNCS ZEEK_OPT_FILES
export -n ZEEK_GEN_CPP ZEEK_REPORT_UNCOMPILABLE ZEEK_CPP_DIR ZEEK_OPT_FILES

ninja

(
    cd ../testing/btest
    ../../auxil/btest/btest -a cpp $btest_opt -f ../../build/CPP-test/diag.$base $rel_test
)
