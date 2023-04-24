# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p proto service community_id < conn.log > conn.log.cut
# @TEST-EXEC: btest-diff conn.log.cut

@load protocols/conn/community-id-logging
