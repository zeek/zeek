# @TEST-EXEC: zeek -r $TRACES/ftp/ipv4.trace %INPUT
# @TEST-EXEC: btest-diff conn.log

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

function mark_conn(state: signature_state, data: string): bool
	{
	add state$conn$service["blah"];
	return T;
	}
