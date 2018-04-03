# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run controllee BROPATH=$BROPATH:.. bro %INPUT frameworks/control/controllee Broker::default_port=65530/tcp
# @TEST-EXEC: btest-bg-run controller BROPATH=$BROPATH:.. bro %INPUT frameworks/control/controller Control::host=127.0.0.1 Control::host_port=65530/tcp Control::cmd=shutdown
# @TEST-EXEC: btest-bg-wait 10

