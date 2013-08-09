# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run sender   bro -Bthreading,logging,comm -C -r $TRACES/web.trace --pseudo-realtime ../sender.bro
# @TEST-EXEC: btest-bg-run receiver bro -Bthreading,logging,comm  ../receiver.bro
# @TEST-EXEC: btest-bg-wait 20
# 
# @TEST-EXEC: btest-diff sender/http.log
# @TEST-EXEC: btest-diff receiver/http.log
# 
# @TEST-EXEC: cat sender/http.log   | $SCRIPTS/diff-remove-timestamps >sender.http.log
# @TEST-EXEC: cat receiver/http.log | $SCRIPTS/diff-remove-timestamps >receiver.http.log
# @TEST-EXEC: cmp sender.http.log receiver.http.log
# 
# @TEST-EXEC: bro -x sender/events.bst | sed 's/^event \[[-0-9.]*\] //g' | grep '^http_' | grep -v http_stats | sed 's/(.*$//g' | $SCRIPTS/diff-remove-timestamps >events.snd.log
# @TEST-EXEC: bro -x receiver/events.bst | sed 's/^event \[[-0-9.]*\] //g' | grep '^http_' | grep -v http_stats | sed 's/(.*$//g' | $SCRIPTS/diff-remove-timestamps  >events.rec.log
# @TEST-EXEC: btest-diff events.rec.log
# @TEST-EXEC: btest-diff events.snd.log
# @TEST-EXEC: cmp events.rec.log events.snd.log
# 
# We don't compare the transmitted event paramerters anymore. With the dynamic
# state in there since 1.6, they don't match reliably.

@TEST-START-FILE sender.bro

@load frameworks/communication/listen

event bro_init()
    {
    capture_events("events.bst");
    }

redef peer_description = "events-send";

# Make sure the HTTP connection really gets out.
# (We still miss one final connection event because we shutdown before
# it gets propagated but that's ok.)
redef tcp_close_delay = 0secs;

# File-analysis fields in http.log won't get set on receiver side correctly,
# one problem is with the way serialization may send a unique ID in place
# of a full value and expect the remote side to associate that unique ID with
# a value it received at an earlier time.  So sometimes modifications the sender# makes to the value aren't seen on the receiver.
function myfh(c: connection, is_orig: bool): string
	{
	return "";
	}

event bro_init() 
	{
	# Ignore all http files.
	Files::register_protocol(Analyzer::ANALYZER_HTTP,
	                         [$get_file_handle = myfh]);
	}

@TEST-END-FILE

#############

@TEST-START-FILE receiver.bro

event bro_init()
    {
    capture_events("events.bst");
    }

redef peer_description = "events-rcv";

redef Communication::nodes += {
    ["foo"] = [$host = 127.0.0.1, $events = /http_.*|signature_match|file_.*/, $connect=T, $retry=1sec]
};

event remote_connection_closed(p: event_peer)
	{
	terminate();
	}

@TEST-END-FILE
