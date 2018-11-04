# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run controllee BROPATH=$BROPATH:.. bro %INPUT frameworks/control/controllee Broker::default_port=$BROKER_PORT
# @TEST-EXEC: btest-bg-run controller BROPATH=$BROPATH:.. bro %INPUT frameworks/control/controller Control::host=127.0.0.1 Control::host_port=$BROKER_PORT Control::cmd=shutdown
# @TEST-EXEC: btest-bg-wait 10

