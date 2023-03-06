# @TEST-EXEC: zeek -b -C -r $TRACES/mixed-vlan-mpls.trace %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff http.log

@load base/protocols/conn
@load base/protocols/http
