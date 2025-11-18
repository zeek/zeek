##! Add Kerberos ticket hashes to the krb.log

@load base/protocols/krb

module KRB;

redef record Info += {
	## Hash of ticket used to authorize request/transaction
	auth_ticket: string &log &optional &deprecated="Remove in v9.1. Use auth_ticket_sha256";
	## Hash of ticket returned by the KDC
	new_ticket:  string &log &optional &deprecated="Remove in v9.1. Use new_ticket_sha256";
	## Hash of ticket used to authorize request/transaction, in sha256
	auth_ticket_sha256: string &log &optional;
	## Hash of ticket returned by the KDC, in sha256
	new_ticket_sha256:  string &log &optional;
};

event krb_ap_request(c: connection, ticket: KRB::Ticket, opts: KRB::AP_Options)
	{
	# Will be overwritten when request is a TGS
	c$krb$request_type = "AP";

	if ( ticket?$ciphertext )
		{
@pragma push ignore-deprecations
		c$krb$auth_ticket = md5_hash(ticket$ciphertext);
@pragma pop ignore-deprecations
		c$krb$auth_ticket_sha256 = sha256_hash(ticket$ciphertext);
		}
	}

event krb_as_response(c: connection, msg: KDC_Response)
	{
	if ( msg$ticket?$ciphertext )
		{
@pragma push ignore-deprecations
		c$krb$new_ticket = md5_hash(msg$ticket$ciphertext);
@pragma pop ignore-deprecations
		c$krb$new_ticket_sha256 = sha256_hash(msg$ticket$ciphertext);
		}
	}

event krb_tgs_response(c: connection, msg: KDC_Response)
	{
	if ( msg$ticket?$ciphertext )
		{
@pragma push ignore-deprecations
		c$krb$new_ticket = md5_hash(msg$ticket$ciphertext);
@pragma pop ignore-deprecations
		c$krb$new_ticket_sha256 = sha256_hash(msg$ticket$ciphertext);
		}
	}
