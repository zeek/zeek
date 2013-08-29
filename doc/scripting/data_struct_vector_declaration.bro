event bro_init()
    {
    local v1: vector of count;
    local v2 = vector(1, 2, 3, 4);
    
    v1[|v1|] = 1;
    v1[|v1|] = 2;
    v1[|v1|] = 3;
    v1[|v1|] = 4;
    
    print fmt("contents of v1: %s", v1);
    print fmt("length of v1: %d", |v1|);
    print fmt("contents of v1: %s", v2);
    print fmt("length of v2: %d", |v2|);
    }
