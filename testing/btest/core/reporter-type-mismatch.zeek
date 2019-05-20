#
# @TEST-EXEC-FAIL: zeek %INPUT >output 2>&1
# @TEST-EXEC:      TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

event foo(a: string)
{
}

event zeek_init()
{
    event foo(42);
}
