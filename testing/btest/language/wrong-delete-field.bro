
# @TEST-EXEC-FAIL: bro %INPUT  >output 2>&1
# @TEST-EXEC: btest-diff output

type X: record {
     a: count;
};

global x: X = [$a=20];

delete x$a;
