# @TEST-EXEC: zcat <$TRACES/smb/smb_many_open_files_500.pcap.gz | zeek -b -Cr - %INPUT
# @TEST-DOC:  Regression test #3523; no output check, just shouldn't crash

redef table_expire_delay = 0.1sec;
redef table_incremental_step = 1;
redef table_expire_interval = 0.1sec;

redef record connection += {
	recent_tcp: set[string] &default=set() &read_expire=3min;
};

event new_packet(c: connection, pkt: pkt_hdr) {
	add c$recent_tcp[cat(pkt$tcp)];
}
