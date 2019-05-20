# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run controllee  BROPATH=$BROPATH:.. zeek -Bbroker %INPUT frameworks/control/controllee Broker::default_port=$BROKER_PORT
# @TEST-EXEC: btest-bg-run controller  BROPATH=$BROPATH:.. zeek -Bbroker %INPUT test-redef frameworks/control/controller Control::host=127.0.0.1 Control::host_port=$BROKER_PORT Control::cmd=configuration_update
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff controllee/.stdout

const test_var = "ORIGINAL VALUE (this should be printed out first)" &redef;

@TEST-START-FILE test-redef.zeek
redef test_var = "NEW VALUE (this should be printed out second)";
@TEST-END-FILE

event zeek_init()
	{
	print test_var;
	Reporter::info("handle zeek_init");
	}
	
event zeek_done()
	{
	print test_var;
	Reporter::info("handle zeek_done");
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

event Control::configuration_update_request()
	{
	Reporter::info("handle Control::configuration_update_request");
	}

event Control::configuration_update_response()
	{
	Reporter::info("handle Control::configuration_update_response");
	}
