# This verifies Zeek's ability to load scripts from stdin.
# @TEST-EXEC: echo 'print "stdin";' | zeek -b >output.implicit
# @TEST-EXEC: echo 'print "stdin";' | zeek -b - >output.explicit
# @TEST-EXEC: echo 'print "stdin";' | zeek -b %INPUT >output.nostdin
# @TEST-EXEC: echo 'print "stdin";' | zeek -b %INPUT - >output.mixed
# @TEST-EXEC: btest-diff output.implicit
# @TEST-EXEC: btest-diff output.explicit
# @TEST-EXEC: btest-diff output.nostdin
# @TEST-EXEC: btest-diff output.mixed

print "test";
