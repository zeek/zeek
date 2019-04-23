# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run controllee BROPATH=$BROPATH:.. zeek %INPUT frameworks/control/controllee Broker::default_port=$BROKER_PORT
# @TEST-EXEC: btest-bg-run controller BROPATH=$BROPATH:.. zeek %INPUT frameworks/control/controller Control::host=127.0.0.1 Control::host_port=$BROKER_PORT Control::cmd=shutdown
# @TEST-EXEC: btest-bg-wait 10

