#
# @TEST-EXEC-FAIL: zeek %INPUT >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

global a: table[count] of count;

event zeek_init()
{
    print a[2];
}

print a[1];

