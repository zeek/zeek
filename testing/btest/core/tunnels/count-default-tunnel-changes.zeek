# @TEST-DOC: Ensure that the tunnel change limitations work in all cases.
#
# @TEST-EXEC: zeek -b -r $TRACES/tunnels/tunnel-direct-bypass.pcap %INPUT > output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff-cut -m ts uid history tunnel_parents conn.log
# @TEST-EXEC: btest-diff-cut -m tunnel.log

@load base/protocols/conn
@load base/frameworks/tunnels

global changed = 0;

event tunnel_changed(c: connection, e: EncapsulatingConnVector)
	{
	++changed;
	}

event zeek_done()
	{
	print fmt("tunnel_changed=%d", changed);
	}
