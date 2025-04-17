# @TEST-DOC: Check optional end_of_match parameter for signature_match() and custom events.
# @TEST-EXEC: zeek -b %INPUT -r $TRACES/http/get.trace
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: btest-diff .stderr

# Default is 1024, so we don't even peek into the second packet.
redef dpd_buffer_size = 1024 * 1024;

module DataEndOffset;

export {
	global portability_match: event(state: signature_state, data: string, end_of_match: count);
	global portability_match: event(state: signature_state, data: string);

	global portability_match_with_msg: event(state: signature_state, msg: string, data: string, end_of_match: count);
	global portability_match_with_msg: event(state: signature_state, msg: string, data: string);
}

@load-sigs ./test.sig

event signature_match(state: signature_state, msg: string, data: string)
	{
	print "signature_match", msg, |data|;
	}

event signature_match(state: signature_state, msg: string, data: string, end_of_match: count)
	{
	print "signature_match with end_of_match", msg, |data|, data[:end_of_match];
	}

event portability_match(state: signature_state, data: string, end_of_match: count)
	{
	print "portability_match with end_of_match", |data|, data[:end_of_match];
	}

event portability_match(state: signature_state, data: string)
	{
	print "portability_match", |data|;
	}

event portability_match_with_msg(state: signature_state, msg: string, data: string, end_of_match: count)
	{
	print "portability_match_with_msg with end_of_match", msg, |data|, end_of_match, data[:end_of_match];
	}

event portability_match_with_msg(state: signature_state, msg: string, data: string)
	{
	print "portability_match_with_msg", msg, |data|;
	}

# @TEST-START-FILE test.sig
signature with-msg {
	ip-proto == tcp
	payload /.*portability.*/  # this is in the second packet.
	event "message"
}

signature my-custom-event {
	ip-proto == tcp
	payload /.*portability.*/  # this is in the second packet.
	event DataEndOffset::portability_match
}

signature my-custom-event2 {
	ip-proto == tcp
	payload /.*portability.*/  # this is in the second packet.
	event DataEndOffset::portability_match_with_msg "custom message"
}
# @TEST-END-FILE
