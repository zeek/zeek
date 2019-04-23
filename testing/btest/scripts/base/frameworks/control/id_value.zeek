# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run controllee  BROPATH=$BROPATH:.. zeek %INPUT only-for-controllee frameworks/control/controllee Broker::default_port=$BROKER_PORT
# @TEST-EXEC: btest-bg-run controller  BROPATH=$BROPATH:.. zeek %INPUT frameworks/control/controller Control::host=127.0.0.1 Control::host_port=$BROKER_PORT Control::cmd=id_value Control::arg=test_var
# @TEST-EXEC: btest-bg-wait -k 10
# @TEST-EXEC: btest-diff controller/.stdout

# This value shouldn't ever be printed to the controllers stdout.
const test_var = "Original value" &redef;

@TEST-START-FILE only-for-controllee.zeek
# This is only loaded on the controllee, but it's sent to the controller 
# and should be printed there.
redef test_var = "This is the value from the controllee";
@TEST-END-FILE

event die()
	{
	terminate();
	}

event Control::id_value_response(id: string, val: string)
	{
	print fmt("Got an id_value_response(%s, %s) event", id, val);
	schedule 2sec { die() };
	}
