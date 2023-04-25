# This test verifies Community ID presence in the notice log, when
# that part of the package is loaded. The test creates one notice
# without connection state and one with, and verifies that the latter
# includes the Community ID value for it.

# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p proto community_id note msg < notice.log > notice.log.cut
# @TEST-EXEC: btest-diff notice.log.cut

@load protocols/conn/community-id-logging
@load frameworks/notice/community-id

redef enum Notice::Type += {
	COMMUNITY_ID_INIT,
	COMMUNITY_ID_CONN_ESTABLISHED,
};

event zeek_init()
	{
	# A notice without connection context
	NOTICE([$note=COMMUNITY_ID_INIT,
	        $msg="Zeek initializing"]);
	}

event connection_established(c: connection)
	{
	# A notice with connection context
	NOTICE([$note=COMMUNITY_ID_CONN_ESTABLISHED,
	        $msg="Connection establishment",
	        $conn=c]);
	}
