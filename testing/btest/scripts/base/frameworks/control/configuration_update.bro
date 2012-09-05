# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run controllee  BROPATH=$BROPATH:.. bro %INPUT frameworks/control/controllee Communication::listen_port=65531/tcp 
# @TEST-EXEC: sleep 5
# @TEST-EXEC: btest-bg-run controller  BROPATH=$BROPATH:.. bro %INPUT test-redef frameworks/control/controller Control::host=127.0.0.1 Control::host_port=65531/tcp Control::cmd=configuration_update
# @TEST-EXEC: sleep 5
# @TEST-EXEC: btest-bg-run controller2 BROPATH=$BROPATH:.. bro %INPUT frameworks/control/controller Control::host=127.0.0.1 Control::host_port=65531/tcp Control::cmd=shutdown
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff controllee/.stdout

redef Communication::nodes = {
	# We're waiting for connections from this host for control.
	["control"] = [$host=127.0.0.1, $class="control", $events=Control::controller_events],
};

const test_var = "ORIGINAL VALUE (this should be printed out first)" &redef;

@TEST-START-FILE test-redef.bro
redef test_var = "NEW VALUE (this should be printed out second)";
@TEST-END-FILE

event bro_init()
	{
	print test_var;
	}
	
event bro_done()
	{
	print test_var;
	}
