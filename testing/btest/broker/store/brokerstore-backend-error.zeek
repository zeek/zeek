# @TEST-DOC: Tests for a regression when evaluating &backend attributes.
# @TEST-EXEC-FAIL: zeek -b %INPUT >output 2>&1
#
# The above test ultimately fails with a call to abort(). Under Linux,
# the "aborted" message is written to zeek's stderr, whereas for MacOS and
# FreeBSD it's directed to the invoking shell's stderr. (The two messages
# also differ in text.) Canonicalize by removing from "output" if present.
# @TEST-EXEC: grep -v Aborted output >tmp && mv tmp output
# @TEST-EXEC: TEST_DIFF_CANONIFIER='grep -v "Remove in v9.1:" | $SCRIPTS/diff-remove-abspath' btest-diff output

function foo(): Broker::BackendType
	{
	}

# This used to crash.
global t: table[string] of count &backend=foo();

event zeek_init()
	{
	print "I shouldn't happen";
	}
