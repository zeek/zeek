# @TEST-EXEC: zeek -b -r $TRACES/http/http-body-match.pcap %INPUT | sort >out
# @TEST-EXEC: btest-diff out

@load-sigs test.sig
@load base/protocols/http

@TEST-START-FILE test.sig
signature http_request_body_AB_prefix {
	http-request-body /^AB/
	event "HTTP request body starting with AB"
}

signature http_request_body_AB_only {
	http-request-body /^AB$/
	event "HTTP request body containing AB only"
}

signature http_request_body_AB_then_CD {
	http-request-body /AB/
	http-request-body /CD/
	event "HTTP request body containing AB and CD, but maybe not be on same request (documented behaviour)"
}

signature http_response_body_CD_prefix {
	http-reply-body /^CD/
	event "HTTP response body starting with CD"
}

signature http_response_body_CD_only {
	http-reply-body /^CD$/
	event "HTTP response body containing CD only"
}
@TEST-END-FILE

event signature_match(state: signature_state, msg: string, data: string)
{
	print(fmt("HTTP body match for %s:%d -> %s:%d with signature '%s', data: '%s'",
		state$conn$id$orig_h, state$conn$id$orig_p,
		state$conn$id$resp_h, state$conn$id$resp_p,
		state$sig_id,
		data
	));
}
