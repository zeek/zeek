@load base/protocols/conn
@load base/protocols/http

event connection_state_remove(c: connection)
    {
    print c;
    }
