# @TEST-EXEC: bro %INPUT
# @TEST-EXEC: btest-diff .stdout

event bro_init()
    {
    local my_ports: set[port];
    # SSH
    add my_ports[22/tcp];
    # HTTPS
    add my_ports[443/tcp];
    # IMAPS
    add my_ports[993/tcp];
    
    # Check for SMTPS 
    if ( 587/tcp !in my_ports )
        {
        add my_ports[587/tcp];
        }
    
    print my_ports;
    }