# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-DOC: Checks that CRLF line endings work in zeek/signature files
# Note the test file itself uses CRLFs and .gitattributes has an entry
# to ensure preservation of the CRLFs.

@TEST-START-FILE test.sig
signature blah
	{
	ip-proto == tcp
	src-port == 21
	payload /.*/
	event "matched"
	}
@TEST-END-FILE

@TEST-START-FILE test.zeek
event zeek_init()
	{
	print "zeek_init";
	}
@TEST-END-FILE

@load test.zeek
@load-sigs test.sig

print "first hello";

@if ( T )
	print "hello T";
@else
	print "hello F";
@endif

print "last hello";
