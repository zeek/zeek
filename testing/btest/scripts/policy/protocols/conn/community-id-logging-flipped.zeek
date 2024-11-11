# @TEST-DOC: Ensure community_id is logged even if the connection is flipped.

# @TEST-EXEC: zeek -b -r $TRACES/tcp/handshake-reorder.trace %INPUT >out
# @TEST-EXEC: zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p proto service community_id < conn.log > conn.log.cut
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff conn.log.cut

@load protocols/conn/community-id-logging

event new_connection(c: connection)
	{
	print "new_connection", c$uid, c$conn$community_id;
	}
