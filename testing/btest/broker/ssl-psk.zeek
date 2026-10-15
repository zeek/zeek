# @TEST-DOC: Without certificates, Broker peers must share the TLS 1.3 pre-shared key and identity.
#
# @TEST-GROUP: broker
#
# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run listen "zeek -b %INPUT connect=F Broker::ssl_psk_key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f >out"
# @TEST-EXEC: $SCRIPTS/wait-for-file listen/listen_ready 20 || (btest-bg-wait -k 1 && false)
#
# @TEST-EXEC: btest-bg-run good_connect "zeek -b %INPUT connect=T Broker::ssl_psk_key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
# @TEST-EXEC: $SCRIPTS/wait-for-file good_connect/connected 20 || (btest-bg-wait -k 1 && false)
#
# @TEST-EXEC: btest-bg-run wrong_key "zeek -b %INPUT connect=T Broker::ssl_psk_key=ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
# @TEST-EXEC: $SCRIPTS/wait-for-file wrong_key/failed 20 || (btest-bg-wait -k 1 && false)
#
# @TEST-EXEC: btest-bg-run wrong_identity "zeek -b %INPUT connect=T Broker::ssl_psk_key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f Broker::ssl_psk_identity=other"
# @TEST-EXEC: $SCRIPTS/wait-for-file wrong_identity/failed 20 || (btest-bg-wait -k 1 && false)
#
# @TEST-EXEC: btest-bg-run default_key "zeek -b %INPUT connect=T"
# @TEST-EXEC: $SCRIPTS/wait-for-file default_key/failed 20 || (btest-bg-wait -k 1 && false)
#
# @TEST-EXEC: btest-bg-run last_connect "zeek -b %INPUT connect=T Broker::ssl_psk_key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff listen/out
# @TEST-EXEC: btest-diff wrong_key/broker.error
# @TEST-EXEC: btest-diff wrong_identity/broker.error
# @TEST-EXEC: btest-diff default_key/broker.error

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
