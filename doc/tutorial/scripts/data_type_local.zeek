function add_two(i: count): count
    {
    local added_two = i+2;
    print fmt("i + 2 = %d", added_two);
    return added_two;
    }

event zeek_init()
    {
    local test = add_two(10);
    }
