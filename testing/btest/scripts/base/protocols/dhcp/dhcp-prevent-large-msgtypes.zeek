# This tests that DHCP log entries do not contain large numbers
# of msg_types.

# @TEST-EXEC: zeek -b -r $TRACES/dhcp/dhcp_flood.pcap -e ' redef DHCP::max_uids_per_log_entry=500; redef DHCP::max_msg_types_per_log_entry=8;' %INPUT
# @TEST-EXEC: btest-diff dhcp.log

@load base/protocols/dhcp
