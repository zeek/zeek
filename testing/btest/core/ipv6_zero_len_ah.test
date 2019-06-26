# @TEST-EXEC: zeek -b -r $TRACES/ipv6_zero_len_ah.trace %INPUT >output
# @TEST-EXEC: btest-diff output

# Shouldn't crash, but we also won't have seq and data fields set of the ip6_ah
# record.

event ipv6_ext_headers(c: connection, p: pkt_hdr)
    {
    print c$id;
    print p;
    }
