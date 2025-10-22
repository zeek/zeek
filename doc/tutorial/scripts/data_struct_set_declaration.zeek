event zeek_init()
    {
    local ssl_ports: set[port];
    local non_ssl_ports = set( 23/tcp, 80/tcp, 143/tcp, 25/tcp );
    
    # SSH
    add ssl_ports[22/tcp];
    # HTTPS
    add ssl_ports[443/tcp];
    # IMAPS
    add ssl_ports[993/tcp];
    
    # Check for SMTPS 
    if ( 587/tcp !in ssl_ports )
        add ssl_ports[587/tcp];
    
    for ( i in ssl_ports )
        print fmt("SSL Port: %s", i);

    for ( i in non_ssl_ports )
        print fmt("Non-SSL Port: %s", i);
    }
