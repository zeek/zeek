# DHCPINFORM leases are special-cased in the code.
# This tests that those leases are correctly logged.

# @TEST-EXEC: zeek -b -r $TRACES/dhcp/dhcp_inform.trace %INPUT
# @TEST-EXEC: btest-diff dhcp.log

@load base/protocols/dhcp
