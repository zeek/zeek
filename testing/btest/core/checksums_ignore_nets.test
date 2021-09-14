# @TEST-EXEC: zeek -b -r $TRACES/chksums/localhost-bad-chksum.pcap "ignore_checksums_nets += {192.168.0.0/16}" %INPUT && mv conn.log conn-worked.log
# @TEST-EXEC: zeek -b -r $TRACES/chksums/localhost-bad-chksum.pcap "ignore_checksums_nets += {192.168.0.0/16, 192.169.0.0/16}" %INPUT && mv conn.log conn-worked-multi-subnets.log
# @TEST-EXEC: zeek -b -r $TRACES/chksums/localhost-bad-chksum.pcap %INPUT && mv conn.log conn-failed.log

# @TEST-EXEC: btest-diff conn-worked.log
# @TEST-EXEC: btest-diff conn-worked-multi-subnets.log
# @TEST-EXEC: btest-diff conn-failed.log

@load base/protocols/conn
