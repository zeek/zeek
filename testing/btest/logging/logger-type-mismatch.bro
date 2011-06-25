#
# @TEST-EXEC-FAIL: bro %INPUT >output 2>&1
# @TEST-EXEC:      btest-diff output

event foo(a: string)
{
}

event bro_init()
{
    event foo(42);
}
