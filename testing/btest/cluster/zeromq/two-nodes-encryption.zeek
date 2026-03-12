# @TEST-DOC: Manager runs the proxy thread and has the curve_server_secretkey set to enable encryption.
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
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff ./manager/out
# @TEST-EXEC: btest-diff ./worker/out


# @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap

redef Cluster::Backend::ZeroMQ::curve_server_publickey = "rq:rM>}U?@Lns47E1%kR.o@n%FcmmsL/@{H8]yf7";
redef Cluster::Backend::ZeroMQ::curve_server_secretkey = "JTKVSB%%)wK0E.X)V>+}o?pNmC{O&4W4b!Ni{Lh6";

redef Cluster::Backend::ZeroMQ::curve_client_publickey = "Yne@$w-vo<fVvi]a<NY6T1ed:M$fCG*[IaLV{hID";
redef Cluster::Backend::ZeroMQ::curve_client_secretkey = "D:)Q[IlAW!ahhC2ac:9*A}h:p?([4%wOTJ%JR%cs";

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

event Cluster::node_up(name: string, id: string) {
	print "node_up", name;
}

event finish(name: string) &is_used {
	terminate();
}
# @TEST-END-FILE
