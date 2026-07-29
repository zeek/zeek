# @TEST-DOC: Regression test for #3538; inserting during robust iteration with a resize should not trigger an assertion.
#
# @TEST-EXEC: zcat <$TRACES/echo-connections.pcap.gz | zeek --load-seeds seeds -b -r - %INPUT table_expire_delay=0.01sec table_incremental_step=10 table_expire_interval=0.5sec

redef record connection += {
	recent_tcp: set[string] &default=set() &read_expire=3min;
};

event new_packet(c: connection, pkt: pkt_hdr) {
	add c$recent_tcp[cat(pkt$tcp)];
}

# @TEST-START-FILE seeds
4140628182
4291381284
402700558
353966048
3712867326
1664171646
1208542792
3074875631
3029468528
1747472994
1495181363
3103230416
3627798802
3491157209
3035073649
2328185080
1698783300
2050917226
208721007
2336112920
1412171239
# @TEST-END-FILE
