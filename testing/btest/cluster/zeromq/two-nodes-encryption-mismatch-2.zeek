# @TEST-DOC: Manager runs the proxy thread in plain mode, but the worker has keys configured. We expect some output on stderr from the worker than indicates the handshake failed.
#
# @TEST-REQUIRES: have-zeromq
#
# @TEST-GROUP: cluster-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT
#
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-no-logger.zeek cluster-layout.zeek
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run worker "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../worker.zeek >out"
#
# Wait for the worker to be up, then wait for it to terminate by itself.
# @TEST-EXEC: $SCRIPTS/wait-for-file worker/.pid 30
# Wait for worker to terminate.
# @TEST-EXEC: while kill -0 $(cat worker/.pid ); do sleep 0.5; done
#
# Initiate manager shutdown
# @TEST-EXEC: kill $(cat manager/.pid )
#
# @TEST-EXEC: btest-bg-wait 30 || true
# @TEST-EXEC: grep "fatal error" worker/.stderr > worker.stderr
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER='sed -E "s,tcp://.*[0-9]+ failed,tcp://<...>:xxxx failed,g" | sed -E "s, line [0-9]+:,line xxx:,g" | $SCRIPTS/diff-remove-abspath'  btest-diff worker.stderr


# @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap

global finish: event(name: string);
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

# If a node comes up that isn't us, send it a finish event.
event Cluster::node_up(name: string, id: string) {
	print "node_up", name;
	Cluster::publish(Cluster::nodeid_topic(id), finish, Cluster::node);
}

# If the worker vanishes, finish the test.
event Cluster::node_down(name: string, id: string) {
	print "node_down", name;
	terminate();
}
# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load ./common.zeek

# The worker has keys configured, but the manager does not.
redef Cluster::Backend::ZeroMQ::curve_server_publickey = "rq:rM>}U?@Lns47E1%kR.o@n%FcmmsL/@{H8]yf7";
redef Cluster::Backend::ZeroMQ::curve_server_secretkey = "JTKVSB%%)wK0E.X)V>+}o?pNmC{O&4W4b!Ni{Lh6";

redef Cluster::Backend::ZeroMQ::curve_client_publickey = "Yne@$w-vo<fVvi]a<NY6T1ed:M$fCG*[IaLV{hID";
redef Cluster::Backend::ZeroMQ::curve_client_secretkey = "D:)Q[IlAW!ahhC2ac:9*A}h:p?([4%wOTJ%JR%cs";


event Cluster::node_up(name: string, id: string) {
	print "node_up", name;
}

event finish(name: string) &is_used {
	terminate();
}

event do_terminate()
	{
	if ( ! zeek_is_terminating() )
		Reporter::fatal("unexpected do_terminate()");
	}

event network_time_init()
	{
	schedule 30sec { do_terminate() };
	}
# @TEST-END-FILE
