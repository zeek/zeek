# Don't run for C++ scripts, they're not compatible.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"

# Shouldn't emit any warnings about not being able to document something
# that's supplied via command line script.

# @TEST-EXEC: unset ZEEK_DISABLE_ZEEKYGEN; zeek %INPUT -e 'redef myvar=10; print myvar' >output 2>&1
# @TEST-EXEC: unset ZEEK_DISABLE_ZEEKYGEN; zeek -e '@load %INPUT print myvar' >>output 2>&1
# @TEST-EXEC: unset ZEEK_DISABLE_ZEEKYGEN; zeek %INPUT -e 'module mymodule; print myvar' >>output 2>&1
# @TEST-EXEC: btest-diff output

const myvar = 5 &redef;
