event connection_state_remove(c: connection)
    {
    print "connection_state_remove";
    print c$uid;
    print c$id;
    for ( s in c$service )
        print s;
    }

event file_state_remove(f: fa_file)
    {
    print "file_state_remove";
    print f$id;
    for ( cid in f$conns )
        {
        print f$conns[cid]$uid;
        print cid;
        }
    print f$source;
    }
