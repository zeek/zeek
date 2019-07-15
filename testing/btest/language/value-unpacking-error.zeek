# @TEST-EXEC-FAIL: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

event zeek_init()
    {
    local [x, y : count] = ["dog", "cat"];
    print x, y;

    local [a: vector of count, b, c, d, e] = [[1, 2], x, y, 1.2];
    print a, b, c, d;
    }