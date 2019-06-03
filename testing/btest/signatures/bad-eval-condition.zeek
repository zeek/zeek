# @TEST-EXEC-FAIL: zeek -r $TRACES/ftp/ipv4.trace %INPUT
# @TEST-EXEC: btest-diff .stderr

@load-sigs blah.sig

@TEST-START-FILE blah.sig
signature blah
	{
	ip-proto == tcp
	src-port == 21
	payload /.*/
	eval mark_conn
	}
@TEST-END-FILE

# wrong function signature for use with signature 'eval' conditions
# needs to be reported
function mark_conn(state: signature_state): bool
	{
	add state$conn$service["blah"];
	return T;
	}
