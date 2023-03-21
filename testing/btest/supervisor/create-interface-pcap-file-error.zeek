# @TEST-DOC: Creating a node with inteface and pcap_file fails.
# @TEST-EXEC: zeek -j -b %INPUT >out
# @TEST-EXEC: btest-diff out

# Providing interface and pcap_file is an error.

event zeek_init()
	{
	print "is_supervisor", Supervisor::is_supervisor();
	local sn = Supervisor::NodeConfig(
		$name="grault",
		$interface="lo",
		$pcap_file="/dev/null",
	);
	local res = Supervisor::create(sn);

	print res != "" ? "PASS (got error)" : " FAIL (no error)", res;
	terminate();
	}
