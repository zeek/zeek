# @TEST-EXEC: zeek -b -r $TRACES/tcp/fin_retransmission.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

event connection_state_remove(c: connection)
    {
    print c$orig;
    print c$resp;
    }
