# @TEST-DOC: Mixing environment variables and script configuration for encryption fails.
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
# @TEST-EXEC-FAIL: ZEEK_CLUSTER_BACKEND_ZEROMQ_CURVE_SERVER_PUBLICKEY='rq:rM>}U?@Lns47E1%kR.o@n%FcmmsL/@{H8]yf7' CLUSTER_NODE=manager zeek -b manager.zeek
# @TEST-EXEC-FAIL: ZEEK_CLUSTER_BACKEND_ZEROMQ_CURVE_SERVER_SECRETKEY='JTKVSB%%)wK0E.X)V>+}o?pNmC{O&4W4b!Ni{Lh6' CLUSTER_NODE=manager zeek -b manager.zeek
# @TEST-EXEC-FAIL: ZEEK_CLUSTER_BACKEND_ZEROMQ_CURVE_CLIENT_PUBLICKEY='Yne@$w-vo<fVvi]a<NY6T1ed:M$fCG*[IaLV{hID' CLUSTER_NODE=worker-1 zeek -b worker.zeek
# @TEST-EXEC-FAIL: ZEEK_CLUSTER_BACKEND_ZEROMQ_CURVE_CLIENT_SECRETKEY='D:)Q[IlAW!ahhC2ac:9*A}h:p?([4%wOTJ%JR%cs' CLUSTER_NODE=worker-1 zeek -b worker.zeek
#
# @TEST-EXEC: btest-diff .stderr

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

event zeek_init() {
	exit(0);
}
# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load ./common.zeek

event zeek_init() {
	exit(0);
}
# @TEST-END-FILE
