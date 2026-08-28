# @TEST-DOC: Tests vector assignment with UINT32_MAX index reports an error
# @TEST-EXEC: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: btest-diff-remove-abspath out

event zeek_init()
    {
    local v: vector of count;
    v[4294967295] = 1;
    print |v|;
    }
