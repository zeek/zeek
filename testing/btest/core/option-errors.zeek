# @TEST-EXEC-FAIL: zeek %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

option testbool;

@TEST-START-NEXT

option testbool : bool;

@TEST-START-NEXT

option testopt = 5;
testopt = 6;
