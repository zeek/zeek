# @TEST-DOC: Test that raw_packet works correctly with a truncated packet
# @TEST-EXEC: zeek -r $TRACES/trunc/trunc-hdr.pcap %INPUT
# @TEST-EXEC: btest-diff weird.log

event raw_packet(p: raw_pkt_hdr) {
        if ( ! p?$ip )
                return;

        if ( p$ip$hl != 20 )
                print p$ip;
}