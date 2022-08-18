# @TEST-REQUIRES: ! grep -q "#define DONT_HAVE_LIBPCAP_DLT_LINUX_SLL2" $BUILD/zeek-config.h
# @TEST-EXEC: zeek -b -C -r $TRACES/linux_dlt_sll2.pcap %INPUT
# @TEST-EXEC: btest-diff .stdout

event arp_request(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
        {
        print mac_src, mac_dst, SPA, SHA, TPA, THA;
        }

event icmp_echo_request(c: connection , info: icmp_info , id: count , seq: count , payload: string )
        {
        print c$id, info, id, seq;
        }

event icmp_echo_reply(c: connection , info: icmp_info , id: count , seq: count , payload: string )
        {
        print c$id, info, id, seq;
        }
