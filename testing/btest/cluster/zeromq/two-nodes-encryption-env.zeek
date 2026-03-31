# @TEST-DOC: Same as two-nodes-encryption, but use environment variables for the manager instead of script variables.
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
# @TEST-EXEC: chmod +x ./run-manager.sh
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && ../run-manager.sh >out"
# @TEST-EXEC: btest-bg-run worker "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../worker.zeek >out"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff ./manager/out
# @TEST-EXEC: btest-diff ./worker/out


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

# The three settings the CLIENT uses.
redef Cluster::Backend::ZeroMQ::curve_server_publickey = "rq:rM>}U?@Lns47E1%kR.o@n%FcmmsL/@{H8]yf7";
redef Cluster::Backend::ZeroMQ::curve_client_publickey = "Yne@$w-vo<fVvi]a<NY6T1ed:M$fCG*[IaLV{hID";
redef Cluster::Backend::ZeroMQ::curve_client_secretkey = "D:)Q[IlAW!ahhC2ac:9*A}h:p?([4%wOTJ%JR%cs";

event Cluster::node_up(name: string, id: string) {
	print "node_up", name;
}

event finish(name: string) &is_used {
	terminate();
}
# @TEST-END-FILE


# @TEST-START-FILE ./run-manager.sh
#!/usr/bin/env bash
#
# The manager needs the server secret and public key *and* the client's secret and public key
# because it creates the XPUB/XSUB sockets (server) *and* connects to them (client).
export ZEEK_CLUSTER_BACKEND_ZEROMQ_CURVE_CLIENT_PUBLICKEY='Yne@$w-vo<fVvi]a<NY6T1ed:M$fCG*[IaLV{hID'
export ZEEK_CLUSTER_BACKEND_ZEROMQ_CURVE_CLIENT_SECRETKEY='D:)Q[IlAW!ahhC2ac:9*A}h:p?([4%wOTJ%JR%cs'
export ZEEK_CLUSTER_BACKEND_ZEROMQ_CURVE_SERVER_PUBLICKEY='rq:rM>}U?@Lns47E1%kR.o@n%FcmmsL/@{H8]yf7'
export ZEEK_CLUSTER_BACKEND_ZEROMQ_CURVE_SERVER_SECRETKEY='JTKVSB%%)wK0E.X)V>+}o?pNmC{O&4W4b!Ni{Lh6'
export CLUSTER_NODE=manager

exec zeek -b ../manager.zeek
# @TEST-END-FILE
