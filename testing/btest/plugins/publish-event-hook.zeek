# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo PublishEvent
# @TEST-EXEC: cp -r %DIR/publish-event-hook-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd` zeek -b Demo::PublishEvent %INPUT > output
# @TEST-EXEC: btest-diff output

redef allow_network_time_forward = F;

redef Cluster::backend = Cluster::CLUSTER_BACKEND_BROKER;

module App;

export {
	global test_event: event(c: count);

	global topic: string = "/test/topic";

	global do_not_publish_topic: string = "/do/not/publish";
}

event zeek_init() &priority=10
	{
	Cluster::publish(topic, test_event, 42);
	Cluster::publish(do_not_publish_topic, test_event, 9999);
	}
