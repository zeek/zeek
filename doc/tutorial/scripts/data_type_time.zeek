event connection_established(c: connection)
    {
    print fmt("%s:  New connection established from %s to %s\n", strftime("%Y/%m/%d %H:%M:%S", network_time()), c$id$orig_h, c$id$resp_h);
    }
