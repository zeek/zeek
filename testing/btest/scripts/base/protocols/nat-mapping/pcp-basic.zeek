# @TEST-DOC: Basic test of PCP handling
# @TEST-EXEC: zeek -C -b -r $TRACES/nat/pcp-basic.pcapng
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff nat-mapping.log

@load base/protocols/conn
@load base/protocols/nat-mapping
