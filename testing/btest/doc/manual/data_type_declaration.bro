# @TEST-EXEC: bro %INPUT
# @TEST-EXEC: btest-diff .stdout

event bro_init()
    {
    local a: int;
    a = 10;
    local b = 10;

    if (a == b)
        {
        print fmt("A: %d, B: %d", a, b);
        }
    }