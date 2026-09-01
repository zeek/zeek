# @TEST-DOC: Verify Broker's default IdentifierUpdate behavior for sender & receiver.
#
# Can't use this test for -O gen-C++ because of multiple simultaneous
# Zeek runs.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# @TEST-GROUP: broker
#
# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run recv NODE=recv zeek -b %INPUT ../recv.zeek
# @TEST-EXEC: btest-bg-run send NODE=send zeek -b %INPUT ../send.zeek test_var=newval
#
# @TEST-EXEC: btest-bg-wait 45
#
# @TEST-EXEC: btest-diff send/.stdout
# @TEST-EXEC: btest-diff recv/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER='grep -v PEER_UNAVAILABLE' btest-diff send/.stderr
# @TEST-EXEC: btest-diff recv/.stderr

# @TEST-START-FILE send.zeek

const test_var = "init" &redef;

event zeek_init()
	{
	Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event reporter_error(t: time, msg: string, location: string)
	{
	if ( msg == "Not publishing ID update, feature disabled: test_var" )
		terminate();
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer lost";
	terminate();
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer added";
	Broker::publish_id("zeek/ids/test", "test_var");
	}

# @TEST-END-FILE

# @TEST-START-FILE recv.zeek

const test_var = "init" &redef;

event check_var()
	{
	if ( test_var == "init" )
		schedule 0.1sec { check_var() };
	else
		{
		print "updated val", test_var;
		terminate();
		}
	}

event zeek_init()
	{
	print "initial val", test_var;
	Broker::subscribe("zeek/ids");
	Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event reporter_error(t: time, msg: string, location: string)
	{
	if ( msg == "Received id-update request, feature disabled: test_var" )
		terminate();
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer added";
	schedule 1sec { check_var() };
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer lost";
	terminate();
	}

# @TEST-END-FILE

# Default: neither sending nor receiving of IdentifierUpdates enabled.
# The sender reports an error, no update results.

# @TEST-START-NEXT
# Sending of IdentifierUpdates enabled, receipt disabled.
# The receiver reports an error, no update results.

@if ( getenv("NODE") == "send" )
redef Broker::enable_identifier_updates = T;
@endif

# @TEST-START-NEXT
# Sending and receiving IdentifierUpdates enabled. An update results.

redef Broker::enable_identifier_updates = T;
