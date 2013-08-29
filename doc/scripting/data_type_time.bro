event connection_established(c: connection)
    {
    print fmt("%s:  New connection established from %s to %s\n", strftime("%Y/%M/%d %H:%m:%S", network_time()), c$id$orig_h, c$id$resp_h);
    }
