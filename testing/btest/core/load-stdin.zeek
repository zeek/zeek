# This verifies Zeek's ability to load scripts from stdin.
#
# Don't run for C++ scripts because the multiple invocations lead to
# some runs having complaints that there are no scripts.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# @TEST-EXEC: echo 'print "stdin";' | zeek -b >output.implicit
# @TEST-EXEC: echo 'print "stdin";' | zeek -b - >output.explicit
# @TEST-EXEC: echo 'print "stdin";' | zeek -b %INPUT >output.nostdin
# @TEST-EXEC: echo 'print "stdin";' | zeek -b %INPUT - >output.mixed
# @TEST-EXEC: btest-diff output.implicit
# @TEST-EXEC: btest-diff output.explicit
# @TEST-EXEC: btest-diff output.nostdin
# @TEST-EXEC: btest-diff output.mixed

print "test";
