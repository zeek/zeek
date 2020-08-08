# @TEST-EXEC: zeek -b -C -r $TRACES/mixed-vlan-mpls.trace %INPUT
# @TEST-EXEC: btest-diff conn.log

@load base/protocols/conn
@load base/protocols/http
@load base/frameworks/dpd
