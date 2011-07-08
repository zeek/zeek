# @TEST-EXEC: bro %INPUT >output
# @TEST-EXEC: btest-diff output

event bro_script_loaded(path: string, level: count)
{
    print level, path;
}
