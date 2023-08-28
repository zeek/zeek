# This tests that DHCP leases are logged in dhcp.log
# The trace has a message of each DHCP message type,
# but only one lease should show up in the logs.

# @TEST-EXEC: zeek -b -r $TRACES/dhcp/dhcp.trace %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff dhcp.log

@load base/protocols/conn
@load base/protocols/dhcp
