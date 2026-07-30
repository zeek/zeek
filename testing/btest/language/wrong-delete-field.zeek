# @TEST-EXEC-FAIL: zeek -b %INPUT  >output 2>&1
# @TEST-EXEC: btest-diff-remove-abspath output

type X: record {
     a: count;
};

global x: X = [$a=20];

delete x$a;
