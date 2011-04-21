#
# @TEST-EXEC: btest-bg-run sender   bro -C -r $TRACES/web.trace --pseudo-realtime ../sender.bro
# @TEST-EXEC: btest-bg-run receiver bro ../receiver.bro
# @TEST-EXEC: btest-bg-wait -k 20
#
# @TEST-EXEC: btest-diff sender/http.log
# @TEST-EXEC: btest-diff receiver/http.log
# @TEST-EXEC: cat receiver/http.log | sed 's/^\([^ ]* \)\{2\}//' >http.rec.log
# @TEST-EXEC: cat sender/http.log | sed 's/^\([^ ]* \)\{2\}//' >http.snd.log
# @TEST-EXEC: cmp http.rec.log http.snd.log
#
# @TEST-EXEC: bro -x sender/events.bst   | sed 's/^Event \[[-0-9.]*\] //g' | sed 's/%events-[^ ]* *//g' | grep '^http_' | grep -v http_stats >events.snd.log
# @TEST-EXEC: bro -x receiver/events.bst | sed 's/^Event \[[-0-9.]*\] //g' | sed 's/%events-[^ ]* *//g' | grep '^http_' | grep -v http_stats >events.rec.log
# @TEST-EXEC: cmp events.rec.log events.snd.log

@TEST-START-FILE sender.bro

@load tcp
@load http-request
@load http-reply
@load http-header
@load http-body
@load http-abstract
@load listen-clear

@load capture-events

redef peer_description = "events-send";

# Make sure the HTTP connection really gets out.
# (We still miss one final connection event because we shutdown before
# it gets propagated but that's ok.)
redef tcp_close_delay = 0secs;

@TEST-END-FILE

#############

@TEST-START-FILE receiver.bro

@load tcp
@load http-request
@load http-reply
@load http-header
@load http-body
@load http-abstract

@load capture-events
@load remote

redef peer_description = "events-rcv";

redef Remote::destinations += {
    ["foo"] = [$host = 127.0.0.1, $events = /http_.*/, $connect=T]
};

event remote_connection_closed(p: event_peer)
	{
	terminate();
	}

@TEST-END-FILE
