# @TEST-DOC: Regression test that ensures sparse index vectors don't segfault
#
# @TEST-EXEC: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

event zeek_init()
    {
    local v1: vector of count = vector(10, 20, 30);
    # Create a sparse index vector with a gap at index 1
    local idx: vector of count;
    idx[0] = 0;
    idx[2] = 1;
    # This crashes with SIGSEGV because idx[1] is uninitialized (nil)
    print v1[idx];
    }
