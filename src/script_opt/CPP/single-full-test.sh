#! /bin/sh

echo $1

base=../../..
test=$base/testing/btest
build=$base/build
gen=CPP-gen.cc

./non-embedded-build >$build/errs 2>&1 || echo non-embedded build failed

export -n ZEEK_USE_CPP
export ZEEK_HASH_DIR=$test ZEEK_GEN_CPP=
cd $test
../../auxil/btest/btest $1 >jbuild-$1.out 2>&1
grep -c '^namespace' $gen
mv $gen $build/
cd $build
ninja >&errs || echo build for $1 failed

export -n ZEEK_GEN_CPP
cd $test
rm -rf .tmp
../../auxil/btest/btest -a cpp -f cpp-test.$1.diag $1
