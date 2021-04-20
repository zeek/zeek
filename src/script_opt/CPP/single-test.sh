#! /bin/sh

echo $1

base=../../..
test=$base/testing/btest
so=$base/src/script_opt/CPP
build=$base/build
gen=CPP-gen-addl.h

export -n ZEEK_USE_CPP
export ZEEK_HASH_DIR=$test ZEEK_ADD_CPP=
cd $test
cp $build/CPP-hashes.dat .
echo >$gen
../../auxil/btest/btest $1 >cpp-build-$1.out 2>&1
grep -c '^namespace' $gen
mv $gen $so
cd $build
ninja >& errs || echo build for $1 failed

export -n ZEEK_ADD_CPP
cd $test
rm -rf .tmp
../../auxil/btest/btest -j -a cpp -f cpp-test.$1.diag $1
