# @TEST-DOC: Test Broker's backpressure mechanism by overwhelming a slow worker.
#
# This test brings up a manager, worker, and proxy with standard cluster
# topology. It streams ping events from the worker to the proxy. It wedges event
# processing on the proxy by locking up its event loop in scriptland, then
# verifies backpressure detection, and subsequent recovery after the proxy
# un-wedges.
#
# This is the same as disconnect-slow-worker, but with worker->proxy overload.
#
# @TEST-GROUP: cluster
#
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_PROXY1_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
# @TEST-EXEC: cp $TEST_BASE/cluster/broker/backpressure/common/*.zeek .
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager zeek -b %INPUT ../manager.zeek"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT ../sender.zeek"
# @TEST-EXEC: btest-bg-run proxy-1 "ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=proxy-1 zeek -b %INPUT ../receiver.zeek"
#
# @TEST-EXEC: btest-bg-wait 60
#
# @TEST-EXEC: btest-diff manager/.stdout
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff proxy-1/.stdout

# Where to send the pings: from worker to proxy.
global ping_topic = Cluster::proxy_topic;

# Where the receiver should notify the sender of termination, after recovery.
global termination_topic = Cluster::worker_topic;
