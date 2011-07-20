# @TEST-EXEC: bro %INPUT >output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

event bro_script_loaded(path: string, level: count)
{
    print level, path;
}
