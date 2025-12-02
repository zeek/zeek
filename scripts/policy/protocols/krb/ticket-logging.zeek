##! Add Kerberos ticket hashes to the krb.log

@load base/protocols/krb

module KRB;

redef record Info += {
	## SHA256 hash of ticket used to authorize request/transaction
	auth_ticket_sha256: string &log &optional;
	## SHA256 hash of ticket returned by the KDC
	new_ticket_sha256:  string &log &optional;
};

event krb_ap_request(c: connection, ticket: KRB::Ticket, opts: KRB::AP_Options)
	{
	# Will be overwritten when request is a TGS
	c$krb$request_type = "AP";

	if ( ticket?$ciphertext )
		c$krb$auth_ticket_sha256 = sha256_hash(ticket$ciphertext);
	}

event krb_as_response(c: connection, msg: KDC_Response)
	{
	if ( msg$ticket?$ciphertext )
		c$krb$new_ticket_sha256 = sha256_hash(msg$ticket$ciphertext);
	}

event krb_tgs_response(c: connection, msg: KDC_Response)
	{
	if ( msg$ticket?$ciphertext )
		c$krb$new_ticket_sha256 = sha256_hash(msg$ticket$ciphertext);
	}
