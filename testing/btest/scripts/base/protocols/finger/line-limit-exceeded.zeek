# @TEST-DOC: Ensures if the line limit is exceeded, there is a violation.
#
# @TEST-EXEC: zeek -r $TRACES/finger/long-request.pcapng %INPUT >out-request
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff out-request
#
# @TEST-EXEC: zeek -r $TRACES/finger/long-reply-line.pcapng %INPUT >out-reply
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff out-reply

@load base/protocols/finger

event finger_request(c: connection, full: bool, username: string, hostname: string) {
	# This may be seen in the reply one: it needs something to reply *to*
	print fmt("Request lengths: username: %d hostname: %d", |username|, |hostname|);
}

event finger_reply(c: connection, reply_line: string) {
	print "BAD BAD BAD, REPLY WAS TOO LARGE";
	print fmt("Reply length: %d:", |reply_line|);
}
