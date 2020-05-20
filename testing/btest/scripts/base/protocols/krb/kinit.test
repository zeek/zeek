# This test exercises many of the Linux kinit options against a KDC

# @TEST-EXEC: zeek -b -r $TRACES/krb/kinit.trace %INPUT > output
# @TEST-EXEC: btest-diff kerberos.log
# @TEST-EXEC: btest-diff output

@load base/protocols/krb

event krb_ap_request(c: connection, ticket: KRB::Ticket, opts: KRB::AP_Options)
	{
	print "KRB_AP_REQUEST";
	print ticket;
	print opts;
	}


