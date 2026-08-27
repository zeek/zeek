# @TEST-DOC: Verify Broker's identifier update outcome on a range of global IDs.
#
# Can't use this test for -O gen-C++ because of multiple simultaneous
# Zeek runs.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# @TEST-GROUP: broker
#
# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run recv "zeek -b ../recv.zeek >recv.out"
# @TEST-EXEC: btest-bg-run send "zeek -b ../send.zeek >send.out"
#
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff recv/recv.out
# @TEST-EXEC: btest-diff recv/.stderr

# @TEST-START-FILE send.zeek

const test_var_const = "sender";
option test_var_option = "sender";
global test_var_plain = "sender";
global test_var_redef = "sender" &redef;

event zeek_init()
	{
	Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer lost";
	terminate();
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer added";

	Broker::publish_id("zeek/ids/test", "test_var_const");
	Broker::publish_id("zeek/ids/test", "test_var_option");
	Broker::publish_id("zeek/ids/test", "test_var_plain");
	Broker::publish_id("zeek/ids/test", "test_var_redef");
	}

# @TEST-END-FILE

# @TEST-START-FILE recv.zeek

const test_var_const = "receiver";
global test_var_const_warned = F;
global test_var_const_changed = F;

option test_var_option = "receiver";
global test_var_option_warned = F;
global test_var_option_changed = F;

global test_var_plain = "receiver";
global test_var_plain_warned = F;
global test_var_plain_changed = F;

global test_var_redef = "receiver";
global test_var_redef_warned = F;
global test_var_redef_changed = F;

event reporter_warning(t: time, msg: string, location: string)
	{
	if ( msg == "Received id-update request for constant id: test_var_const" )
		test_var_const_warned = T;
	if ( msg == "Received id-update request for config option id: test_var_option" )
		test_var_option_warned = T;
	}

event check_updates()
	{
	if ( test_var_const == "sender" && ! test_var_const_changed )
		{
		test_var_const_changed = T;
		print "updated test_var_const";
		}

	if ( test_var_option == "sender" && ! test_var_option_changed )
		{
		test_var_option_changed = T;
		print "updated test_var_option";
		}

	if ( test_var_plain == "sender" && ! test_var_plain_changed )
		{
		test_var_plain_changed = T;
		print "updated test_var_plain";
		}

	if ( test_var_redef == "sender" && ! test_var_redef_changed )
		{
		test_var_redef_changed = T;
		print "updated test_var_redef";
		}

	# Stop when all conditions match the expected final outcome.
	if ( test_var_const_warned == T &&
	     test_var_const_changed == F &&
	     test_var_option_warned == T &&
	     test_var_option_changed == F &&
	     test_var_plain_warned == F &&
	     test_var_plain_changed == T &&
	     test_var_redef_warned == F &&
	     test_var_redef_changed == T )
		{
		terminate();
		}

	schedule 0.1sec { check_updates() };
	}

event zeek_init()
	{
	Broker::subscribe("zeek/ids");
	Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer added";
	schedule 1sec { check_updates() };
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer lost";
	terminate();
	}

# @TEST-END-FILE
