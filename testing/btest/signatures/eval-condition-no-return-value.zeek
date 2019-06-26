# @TEST-EXEC: zeek -r $TRACES/ftp/ipv4.trace %INPUT
# @TEST-EXEC: btest-diff .stdout
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

function mark_conn(state: signature_state, data: string): bool
	{
	print "Called";
	}
