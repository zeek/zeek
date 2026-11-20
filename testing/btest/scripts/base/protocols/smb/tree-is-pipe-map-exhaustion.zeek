# @TEST-DOC: Test capping of tree_is_pipe_map
#
# @TEST-EXEC: zcat <$TRACES/smb/tree-is-pipe-map-exhaustion.pcap.gz |zeek -b -C -r - %INPUT >out
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m weird.log
# @TEST-EXEC: btest-diff out

@load base/protocols/conn
@load base/protocols/smb

event smb_discarded_tree_is_pipe_map(c: connection, size: count)
	{
	print "smb_discarded_tree_is_pipe_map", c$uid, size;
	}
