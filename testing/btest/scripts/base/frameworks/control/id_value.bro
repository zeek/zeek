# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run controllee  BROPATH=$BROPATH:.. bro %INPUT only-for-controllee frameworks/control/controllee Communication::listen_port=65532/tcp 
# @TEST-EXEC: btest-bg-run controller  BROPATH=$BROPATH:.. bro %INPUT frameworks/control/controller Control::host=127.0.0.1 Control::host_port=65532/tcp Control::cmd=id_value Control::arg=test_var
# @TEST-EXEC: btest-bg-wait -k 10
# @TEST-EXEC: btest-diff controller/.stdout

redef Communication::nodes = {
	# We're waiting for connections from this host for control.
	["control"] = [$host=127.0.0.1, $class="control", $events=Control::controller_events],
};

# This value shouldn't ever be printed to the controllers stdout.
const test_var = "Original value" &redef;

@TEST-START-FILE only-for-controllee.bro
# This is only loaded on the controllee, but it's sent to the controller 
# and should be printed there.
redef test_var = "This is the value from the controllee";
@TEST-END-FILE

event Control::id_value_response(id: string, val: string)
	{
	print fmt("Got an id_value_response(%s, %s) event", id, val);
	terminate();
	}
