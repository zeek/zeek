# @TEST-EXEC: zeek -r $TRACES/tls/ecdhe.pcap %INPUT
# @TEST-EXEC: btest-diff netcontrol.log
# @TEST-EXEC: btest-diff openflow.log

@load base/frameworks/netcontrol

global of_controller: OpenFlow::Controller;

event NetControl::init()
	{
	of_controller = OpenFlow::log_new(42);
	local netcontrol_of = NetControl::create_openflow(of_controller);
	NetControl::activate(netcontrol_of, 0);
	}

event connection_established(c: connection)
	{
	NetControl::quarantine_host(c$id$orig_h, 8.8.8.8, 192.169.18.1, 10hrs);
	}
