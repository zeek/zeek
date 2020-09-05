# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

global my_count: count;

type MyRecord: record {
	f: count &default=my_count;
};

# This global initialization encounters the uninitialized 'my_count' when
# evaluating the &default expression.  The test simply checking that the
# interpreter exception is caught and at least fails out with a nice error
# message instead of letting an uncaught exception cause termination.
global my_record = MyRecord();
