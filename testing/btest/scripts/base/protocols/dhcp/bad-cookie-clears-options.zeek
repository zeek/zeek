# @TEST-DOC: Regression test that ensures bad DHCP cookies don't leak into later messages.
#
# @TEST-EXEC: zeek -b -r $TRACES/dhcp/dhcp_bad_cookie_option_retention.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/protocols/dhcp

# Prevent DPD from removing the analyzer after the bad-cookie violation, so the
# retained option state is observable on the following valid message.
redef DPD::ignore_violations += { Analyzer::ANALYZER_DHCP };

event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
	{
	local n = options?$options ? |options$options| : 0;
	print fmt("dhcp_message xid=0x%x option_count=%d", msg$xid, n);
	}
