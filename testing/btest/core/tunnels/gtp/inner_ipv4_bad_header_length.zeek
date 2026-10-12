# @TEST-DOC: Verify GTPv1 pkt_hdr construction does not underflow the inner IPv4 payload length (and expose OOB TCP fields).
#
# @TEST-EXEC: zeek -b -r $TRACES/tunnels/gtp/gtp-inner-ipv4-hdrlen-overrun.pcap %INPUT >out
#
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: test ! -f analyzer.log

event gtpv1_g_pdu_packet(outer: connection, inner_gtp: gtpv1_hdr, inner_ip: pkt_hdr)
    {
    print "inner", inner_ip$ip$hl, inner_ip$ip$len, inner_ip$ip$p, inner_ip?$tcp;

    if ( inner_ip?$tcp )
        print "BAD: GTP inner pkt_hdr exposed TCP fields from invalid IPv4 payload",
              inner_ip$tcp$sport, inner_ip$tcp$dport, inner_ip$tcp$seq,
              inner_ip$tcp$ack, inner_ip$tcp$hl, inner_ip$tcp$dl;
    }
