# The format string below should end up as a literal part of the reporter's
# error message to stderr and shouldn't be replaced internally.
#
# @TEST-EXEC-FAIL: bro %INPUT >output 2>&1
# @TEST-EXEC:      TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

event bro_init()
{
    event dont_interpret_this("%s");
}
