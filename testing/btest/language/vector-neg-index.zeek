# @TEST-DOC: check for errors for negative vector indexes that are too small
# @TEST-EXEC: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

event zeek_init()
{
	local v = vector( 1, 2, 3, 4, 5 );
	print v[-1], v[-3], v[-5], v[-7];
}
