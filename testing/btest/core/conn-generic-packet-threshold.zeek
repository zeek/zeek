# @TEST-EXEC: echo "Generic threshold crossed:" > out
# @TEST-EXEC: zeek -b -C -r $TRACES/http/get.trace %INPUT >> out
# @TEST-EXEC: zeek -b -C -r $TRACES/dns/long-connection.pcap %INPUT >> out
# @TEST-EXEC: zeek -b -C -r $TRACES/communityid/sctp.pcap %INPUT >> out
# @TEST-EXEC: echo "\nGeneric threshold not crossed:" >> out
# @TEST-EXEC: zeek -b -C -r $TRACES/tcp/syn.pcap %INPUT >> out
# @TEST-EXEC: zeek -b -C -r $TRACES/dns/dns-binds.pcap %INPUT >> out
# @TEST-EXEC: zeek -b -C -r $TRACES/http/get.trace %INPUT ConnThreshold::generic_packet_threshold=15 >> out

# @TEST-EXEC: btest-diff out

event new_connection(c: connection)
	{ print fmt("new_connection: %s", c$id); }

event conn_generic_packet_threshold_crossed(c: connection)
	{ print fmt("conn_generic_packet_threshold_crossed: %s", c$id); }
