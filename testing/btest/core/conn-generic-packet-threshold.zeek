# @TEST-EXEC: echo "=== Generic threshold crossed ===" > out
# @TEST-EXEC: zeek -b -C -r $TRACES/http/get.trace %INPUT >> out
# @TEST-EXEC: zeek -b -C -r $TRACES/dns/long-connection.pcap %INPUT >> out
# @TEST-EXEC: zeek -b -C -r $TRACES/communityid/sctp.pcap %INPUT >> out
# @TEST-EXEC: zeek -b -C -r $TRACES/http/get.trace %INPUT ConnThreshold::generic_packet_thresholds+={10} >> out
# @TEST-EXEC: echo "=== Generic threshold not crossed ===" >> out
# @TEST-EXEC: zeek -b -C -r $TRACES/tcp/syn.pcap %INPUT >> out
# @TEST-EXEC: zeek -b -C -r $TRACES/dns/dns-binds.pcap %INPUT >> out
# @TEST-EXEC: zeek -b -C -r $TRACES/http/get.trace %INPUT ConnThreshold::generic_packet_thresholds={15} >> out

# @TEST-EXEC: btest-diff out

redef ConnThreshold::generic_packet_thresholds = {5};

event new_connection(c: connection)
	{ print fmt("new_connection: %s", c$id); }

event conn_generic_packet_threshold_crossed(c: connection, threshold: count)
	{ print fmt("conn_generic_packet_threshold_crossed: %s at %d", c$id, threshold); }
