event zeek_init()
    {
    local addr_vector: vector of addr = vector(1.2.3.4, 2.3.4.5, 3.4.5.6);

    for ( i in addr_vector )
        print mask_addr(addr_vector[i], 18);
    }
