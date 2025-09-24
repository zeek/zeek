# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run controllee ZEEKPATH=$ZEEKPATH:.. zeek -b %INPUT frameworks/control/controllee Broker::default_port=$BROKER_PORT
# @TEST-EXEC: btest-bg-run controller ZEEKPATH=$ZEEKPATH:.. zeek -b %INPUT frameworks/control/controller Control::host=127.0.0.1 Control::host_port=$BROKER_PORT Control::cmd=shutdown
# @TEST-EXEC: btest-bg-wait 20

# This ensures the controllee script starts listening using Broker.
redef Cluster::backend = Cluster::CLUSTER_BACKEND_BROKER;
