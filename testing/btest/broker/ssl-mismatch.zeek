# @TEST-GROUP: broker
#
# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run listen "zeek -b %INPUT connect=F Broker::disable_ssl=T"
# @TEST-EXEC: $SCRIPTS/wait-for-file listen/listen_ready 20 || (btest-bg-wait -k 1 && false)
#
# @TEST-EXEC: btest-bg-run good_connect "zeek -b %INPUT connect=T Broker::disable_ssl=T"
# @TEST-EXEC: $SCRIPTS/wait-for-file good_connect/connected 20 || (btest-bg-wait -k 1 && false)
#
# @TEST-EXEC: btest-bg-run bad_connect "zeek -b %INPUT connect=T Broker::disable_ssl=F"
# @TEST-EXEC: $SCRIPTS/wait-for-file bad_connect/failed 20 || (btest-bg-wait -k 1 && false)
#
# @TEST-EXEC: btest-bg-run last_connect "zeek -b %INPUT connect=T Broker::disable_ssl=T"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff bad_connect/broker.error
#
# And again, now reversing the SSL mismatch between client/server...
#
# @TEST-EXEC: btest-bg-run listen_rev "zeek -b %INPUT connect=F Broker::disable_ssl=F"
# @TEST-EXEC: $SCRIPTS/wait-for-file listen_rev/listen_ready 20 || (btest-bg-wait -k 1 && false)
#
# @TEST-EXEC: btest-bg-run good_connect_rev "zeek -b %INPUT connect=T Broker::disable_ssl=F"
# @TEST-EXEC: $SCRIPTS/wait-for-file good_connect_rev/connected 20 || (btest-bg-wait -k 1 && false)
#
# @TEST-EXEC: btest-bg-run bad_connect_rev "zeek -b %INPUT connect=T Broker::disable_ssl=T"
# @TEST-EXEC: $SCRIPTS/wait-for-file bad_connect_rev/failed 20 || (btest-bg-wait -k 1 && false)
#
# @TEST-EXEC: btest-bg-run last_connect_rev "zeek -b %INPUT connect=T Broker::disable_ssl=F"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff bad_connect_rev/broker.error

option connect = T;
global num_connections = 0;

event zeek_init()
	{
	local p = to_port(getenv("BROKER_PORT"));
	if ( connect )
		Broker::__peer_no_retry("127.0.0.1", p);
	else
		{
		local actual = Broker::listen("127.0.0.1", p);
		system("touch listen_ready");
		}
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer added";
	++num_connections;

	if ( connect )
		{
		system("touch connected");
		terminate();
		}
	else if ( num_connections == 2 )
		terminate();
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer lost";
	}

event Broker::error(code: Broker::ErrorCode, msg: string) &priority=-10
	{
	if ( connect )
		{
		local f = open("broker.error");
		print f, code;
		close(f);
		system("touch failed");
		terminate();
		}
	}
