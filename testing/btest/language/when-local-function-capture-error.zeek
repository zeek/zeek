# @TEST-DOC: Tests that a capture in a function that doesn't exist doesn't crash
# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TeST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

function f() {
        local x = 1;
        local y = 2;

        when [x, z] ( T == T )
                {
                print "hmm?", x, y;
                }
        timeout 100msec
                {
                print "timeout";
                }
}
