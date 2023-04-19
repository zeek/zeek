# @TEST-DOC: Check that Cluster::publish_hrw() and Cluster::publish_rr() do not cause an abort when provided with wrongly typed arguments.
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

@load base/frameworks/cluster

type R: record {
	a: string;
};

event test_send(r: R) { }

event zeek_init()
	{
	Cluster::publish_hrw("/topic", 1234/tcp, test_send, [$a="a"]);

	Cluster::publish_hrw(0, 1234/tcp, test_send, [$a="a"]);

	Cluster::publish_rr("/topic", "val", test_send, [$a="b"]);

	Cluster::publish_rr(Cluster::Pool(), 1234/tcp, test_send, [$a="c"]);
	}
