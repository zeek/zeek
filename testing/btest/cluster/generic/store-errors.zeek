# @TEST-DOC: Test errors of cluster bifs
#
# @TEST-EXEC: zeek --parse-only -b %INPUT
# @TEST-EXEC-FAIL: zeek -b %INPUT frameworks/cluster/backend/zeromq
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

event zeek_init()
	{
	Cluster::create_store("my-store");
	}

# @TEST-START-NEXT
event zeek_init()
	{
	Broker::create_master("my-store");
	}

# @TEST-START-NEXT
event zeek_init()
	{
	Broker::create_clone("my-store");
	}
