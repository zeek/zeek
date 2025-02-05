# Test verifies that mDNS broadcasts are not logged by default.
# @TEST-EXEC: zeek -b -C -r $TRACES/dns/mdns.pcap %INPUT
# @TEST-EXEC: touch notice.log
# @TEST-EXEC: btest-diff notice.log

##! First test - no log

@load base/protocols/dns
@load policy/protocols/dns/detect-external-names

redef Site::local_zones +=  {"example.inalid"};

@TEST-START-NEXT

##! second test - should output log due to changed config

@load base/protocols/dns
@load policy/protocols/dns/detect-external-names
@load base/frameworks/config

redef Site::local_zones +=  {"example.inalid"};

event zeek_init()
	{
	print Site::local_nets;
	Config::set_value("DNS::skip_resp_host_port_pairs", set());
	}
