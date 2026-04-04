# @TEST-DOC: Tests handling of Kerberos data received via GSS-API in SPNEGO authenticaton for DCE-RPC
#
# @TEST-EXEC: zeek -Cr $TRACES/dce-rpc/kerberos135_auth.pcapng %INPUT > output.135
# @TEST-EXEC: mv kerberos.log kerberos.log.135
# @TEST-EXEC: zeek -Cr $TRACES/dce-rpc/kerberos445_auth.pcapng %INPUT > output.445
# @TEST-EXEC: mv kerberos.log kerberos.log.445
# @TEST-EXEC: btest-diff output.135
# @TEST-EXEC: btest-diff kerberos.log.135
# @TEST-EXEC: btest-diff output.445
# @TEST-EXEC: btest-diff kerberos.log.445

event krb_ap_request(c: connection, ticket: KRB::Ticket, opts: KRB::AP_Options)
	{
	print "krb_ap_request";
	}

event krb_ap_response(c: connection)
	{
	print "krb_ap_response";
	}
