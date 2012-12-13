# @TEST-EXEC: bro -b -C -r $TRACES/wikipedia.trace discarder-ip.bro >output
# @TEST-EXEC: bro -b -C -r $TRACES/wikipedia.trace discarder-tcp.bro >>output
# @TEST-EXEC: bro -b -C -r $TRACES/wikipedia.trace discarder-udp.bro >>output
# @TEST-EXEC: bro -b -C -r $TRACES/icmp/icmp-destunreach-udp.pcap discarder-icmp.bro >>output
# @TEST-EXEC: btest-diff output

@TEST-START-FILE discarder-ip.bro

event bro_init()
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

@TEST-START-FILE discarder-tcp.bro

event bro_init()
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

@TEST-START-FILE discarder-udp.bro

event bro_init()
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

@TEST-START-FILE discarder-icmp.bro

event bro_init()
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
