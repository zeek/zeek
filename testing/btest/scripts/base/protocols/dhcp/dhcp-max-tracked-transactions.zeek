# @TEST-DOC: Test that join_data entries are removed when max_tracked_transactions is reached.

# @TEST-EXEC: zeek -b -r $TRACES/dhcp/dhcp-unique-xid-join-data-growth.pcapng %INPUT >out
# @TEST-EXEC: btest-diff-cut -m dhcp.log
# @TEST-EXEC: btest-diff-cut -m weird.log
# @TEST-EXEC: btest-diff out

@load base/frameworks/notice/weird
@load base/protocols/dhcp

redef DHCP::max_tracked_transactions = 5;

module DHCP;

event zeek_done()
	{
	print "DHCP::join_data", |join_data|;
	print "DHCP::join_data_ordered", |join_data_ordered|;
	}
