#
# @TEST-EXEC-FAIL: bro %INPUT >output 2>&1
# @TEST-EXEC:      btest-diff output

event bro_init()
{
    print TESTFAILURE;
}
