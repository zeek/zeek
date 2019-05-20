# A test of signature loading using @load-sigs.

# @TEST-EXEC: zeek -C -r $TRACES/wikipedia.trace %INPUT >output
# @TEST-EXEC: btest-diff output

@load-sigs ./subdir/mysigs.sig

event signature_match(state: signature_state, msg: string, data: string)
	{
	print state$conn$id;
	print msg;
	print data;
	}

@TEST-START-FILE subdir/mysigs.sig
signature my-sig {
ip-proto == tcp
payload /GET \/images/
event "works"
}
@TEST-END-FILE
