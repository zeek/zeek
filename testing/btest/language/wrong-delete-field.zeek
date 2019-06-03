# @TEST-EXEC-FAIL: zeek -b %INPUT  >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

type X: record {
     a: count;
};

global x: X = [$a=20];

delete x$a;
