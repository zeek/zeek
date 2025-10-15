event zeek_init()
    {
    local addr_vector: vector of addr = vector(1.2.3.4, 2.3.4.5, 3.4.5.6);

    for ( _, a in addr_vector )
        print mask_addr(a, 18);
    }
