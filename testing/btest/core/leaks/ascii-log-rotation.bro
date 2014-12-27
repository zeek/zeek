# Needs perftools support.
#
# @TEST-SERIALIZE: comm
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: bro  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: btest-bg-run receiver HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local bro -b -m ../receiver.bro
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run sender HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local bro -b -m ../sender.bro
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-wait 60

@TEST-START-FILE sender.bro

@load base/frameworks/communication
@load base/protocols/dns

redef Communication::nodes += {
    ["foo"] = [$host = 127.0.0.1, $connect=T]
};

global write_count: count = 0;

event do_write()
	{
	print "do_write";
	local cid: conn_id = conn_id($orig_h=1.2.3.4,$orig_p=1/tcp,
	                             $resp_h=5.6.7.8,$resp_p=2/tcp);
	local dns_info_dummy = DNS::Info($ts=network_time(), $uid="FAKE",
	                                 $id=cid, $proto=tcp);
	Log::write(DNS::LOG, dns_info_dummy);
	schedule .1sec { do_write() };
	++write_count;

	if ( write_count == 200 )
		terminate();
	}

event remote_connection_handshake_done(p: event_peer)
	{
	print "remote_connection_handshake_done", p;
	schedule .1sec { do_write() };
	}

event remote_connection_closed(p: event_peer)
	{
	print "remote_connection_closed", p;
	}

@TEST-END-FILE

@TEST-START-FILE receiver.bro

@load frameworks/communication/listen
@load base/protocols/dns

redef Communication::nodes += {
	["foo"] = [$host = 127.0.0.1, $connect=F, $request_logs=T]
};

redef Log::default_rotation_interval = 2sec;

event remote_connection_handshake_done(p: event_peer)
	{
	print "remote_connection_handshake_done", p;
	}

event remote_connection_closed(p: event_peer)
	{
	print "remote_connection_closed", p;
	terminate();
	}

@TEST-END-FILE
