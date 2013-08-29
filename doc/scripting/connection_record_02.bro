@load base/protocols/conn
@load base/protocols/dns

event connection_state_remove(c: connection)
    {
    print c;
    }
