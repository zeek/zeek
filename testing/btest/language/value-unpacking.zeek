# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
    {
    local [x, y : count] = ["dog", 10];
    print x, y;

    local [a: vector of count, b, c, d] = [[1, 2], x, y, 1.2];
    print a, b, c, d;
    }