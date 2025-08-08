# @TEST-DOC: Cluster::on_subscribe and Cluster::on_unsubscribe hooks
#
# @TEST-EXEC: zeek --parse-only -b %INPUT
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stdout

hook Cluster::on_subscribe(topic: string)
	{
	print "on_subscribe", topic;
	}

hook Cluster::on_unsubscribe(topic: string)
	{
	print "on_unsubscribe", topic;
	}

event zeek_init()
	{
	Cluster::subscribe("/my_topic");
	Cluster::unsubscribe("/my_topic");
	Cluster::unsubscribe("/my_topic");
	Cluster::subscribe("/my_topic2");
	}
