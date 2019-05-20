# Shouldn't emit any warnings about not being able to document something
# that's supplied via command line script.

# @TEST-EXEC: unset BRO_DISABLE_BROXYGEN; zeek %INPUT -e 'redef myvar=10; print myvar' >output 2>&1
# @TEST-EXEC: btest-diff output

const myvar = 5 &redef;
