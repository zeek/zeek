# @TEST-EXEC: zeek -b -C -r $TRACES/wikipedia.trace discarder-ip.zeek >output
# @TEST-EXEC: zeek -b -C -r $TRACES/wikipedia.trace discarder-tcp.zeek >>output
# @TEST-EXEC: zeek -b -C -r $TRACES/wikipedia.trace discarder-udp.zeek >>output
# @TEST-EXEC: zeek -b -C -r $TRACES/icmp/icmp-destunreach-udp.pcap discarder-icmp.zeek >>output
# @TEST-EXEC: btest-diff output

@TEST-START-FILE discarder-ip.zeek

event zeek_init()
	{
	print "################ IP Discarder ################";
	}

function discarder_check_ip(p: pkt_hdr): bool
    {
    if ( p?$ip && p$ip$src == 141.142.220.118 && p$ip$dst == 208.80.152.2 )
        return F;
	return T;
    }


event new_packet(c: connection, p: pkt_hdr)
    {
    print c$id;
    }

@TEST-END-FILE

@TEST-START-FILE discarder-tcp.zeek

event zeek_init()
    {
    print "################ TCP Discarder ################";
    }

function discarder_check_tcp(p: pkt_hdr, d: string): bool
    {
    if ( p$tcp$flags == TH_SYN )
        return F;
    return T;
    }

event new_packet(c: connection, p: pkt_hdr)
    {
    if ( p?$tcp )
        print c$id;
    }

@TEST-END-FILE

@TEST-START-FILE discarder-udp.zeek

event zeek_init()
    {
    print "################ UDP Discarder ################";
    }

function discarder_check_udp(p: pkt_hdr, d: string): bool
    {
    if ( p?$ip6 )
        return F;
    return T;
    }

event new_packet(c: connection, p: pkt_hdr)
    {
    if ( p?$udp )
        print c$id;
    }

@TEST-END-FILE

@TEST-START-FILE discarder-icmp.zeek

event zeek_init()
    {
    print "################ ICMP Discarder ################";
    }

function discarder_check_icmp(p: pkt_hdr): bool
    {
    print fmt("Discard icmp packet: %s", p$icmp);
    return T;
    }

event new_packet(c: connection, p: pkt_hdr)
    {
    if ( p?$icmp )
        print c$id;
    }

@TEST-END-FILE
