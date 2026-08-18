# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: btest-diff-remove-abspath .stderr

option testbool;

# @TEST-START-NEXT

option testbool : bool;

# @TEST-START-NEXT

option testopt = 5;
testopt = 6;
