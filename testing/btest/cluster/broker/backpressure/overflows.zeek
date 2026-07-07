# @TEST-DOC: Test Broker's backpressure mechanisms by overwhelming a slow endpoint
#
# This test brings up a manager, worker, and proxy with standard cluster
# topology. It then iterates through combinations of two dimensions: (1)
# Broker's backpressure policy and (2) the direction of the backpressure on the
# peering (from worker -> proxy, and proxy -> worker). For each, the test locks
# up event processing in the receiver, triggering backpressure. It then verifies
# that the sender observes it (depending on the policy), unlocks the receiver,
# and verifies recovery. Concurrently, the manager sends its own type of pings
# to the sender, which the sender returns. This should continue at all times,
# regardless of backpressure in other peerings.
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
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager zeek -b ../common.zeek ../manager.zeek %INPUT"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b ../common.zeek %INPUT"
# @TEST-EXEC: btest-bg-run proxy-1 "ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=proxy-1 zeek -b ../common.zeek %INPUT"
#
# @TEST-EXEC: btest-bg-wait 60
#
# @TEST-EXEC: btest-diff manager/.stdout
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff proxy-1/.stdout

# Test: Worker -> proxy load, disconnect on backpressure.

redef Broker::peer_overflow_policy = "disconnect";

# Send pings from worker to proxy.
redef ping_topic = Cluster::proxy_topic;

# How the receiver should notify the sender: it's a worker.
redef termination_topic = Cluster::worker_topic;

@if ( Cluster::node == "worker-1" )
@load ./sender.zeek
@endif

@if ( Cluster::node == "proxy-1" )
@load ./receiver.zeek
@endif

# @TEST-START-NEXT
# Test: Proxy -> worker load, disconnect on backpressure.

redef Broker::peer_overflow_policy = "disconnect";
redef ping_topic = Cluster::worker_topic;
redef termination_topic = Cluster::proxy_topic;

@if ( Cluster::node == "proxy-1" )
@load ./sender.zeek
@endif

@if ( Cluster::node == "worker-1" )
@load ./receiver.zeek
@endif

# @TEST-START-NEXT
# Test: Worker -> proxy load, drop oldest message on backpressure.

redef Broker::peer_overflow_policy = "drop_oldest"; # This is the default
redef ping_topic = Cluster::proxy_topic;
redef termination_topic = Cluster::worker_topic;

@if ( Cluster::node == "worker-1" )
@load ./sender.zeek
@endif

@if ( Cluster::node == "proxy-1" )
@load ./receiver.zeek
@endif

# @TEST-START-NEXT
# Test: Proxy -> worker load, drop oldest message on backpressure.

redef Broker::peer_overflow_policy = "drop_oldest"; # This is the default
redef ping_topic = Cluster::worker_topic;
redef termination_topic = Cluster::proxy_topic;

@if ( Cluster::node == "proxy-1" )
@load ./sender.zeek
@endif

@if ( Cluster::node == "worker-1" )
@load ./receiver.zeek
@endif

# @TEST-START-NEXT
# Test: Worker -> proxy load, drop newest message on backpressure.

redef Broker::peer_overflow_policy = "drop_newest";
redef ping_topic = Cluster::proxy_topic;
redef termination_topic = Cluster::worker_topic;

@if ( Cluster::node == "worker-1" )
@load ./sender.zeek
@endif

@if ( Cluster::node == "proxy-1" )
@load ./receiver.zeek
@endif

# @TEST-START-NEXT
# Test: Proxy -> worker load, drop newest message on backpressure.

redef Broker::peer_overflow_policy = "drop_newest";
redef ping_topic = Cluster::worker_topic;
redef termination_topic = Cluster::proxy_topic;

@if ( Cluster::node == "proxy-1" )
@load ./sender.zeek
@endif

@if ( Cluster::node == "worker-1" )
@load ./receiver.zeek
@endif
