event bro_init()
    {
    # Declaration of the table.
    local ssl_services: table[string] of port;

    # Initialize the table.
    ssl_services = table(["SSH"] = 22/tcp, ["HTTPS"] = 443/tcp);

    # Insert one key-yield pair into the table.
    ssl_services["IMAPS"] = 993/tcp;

    # Check if the key "SMTPS" is not in the table.
    if ( "SMTPS" !in ssl_services )
        ssl_services["SMTPS"] = 587/tcp;

    # Iterate over each key in the table.
    for ( k in ssl_services )
        print fmt("Service Name:  %s - Common Port: %s", k, ssl_services[k]);
    }
