module KRB;

redef record Info += {
	## Hash of ticket used to authorize request/transaction
	auth_ticket: string &log &optional;
	## Hash of ticket returned by the KDC
	new_ticket:  string &log &optional;
};

event krb_ap_request(c: connection, ticket: KRB::Ticket, opts: KRB::AP_Options)
	{
	if ( c?$krb && c$krb$logged )
		return;
	
	local info: Info;

	if ( !c?$krb )
		{
		info$ts  = network_time();
		info$uid = c$uid;
		info$id  = c$id;
		}
	else
		info = c$krb;

	info$request_type = "AP"; # Will be overwritten when request is a TGS
	if ( ticket?$ciphertext )
		info$auth_ticket = md5_hash(ticket$ciphertext);

	c$krb = info;
	}

event krb_as_response(c: connection, msg: KDC_Response)
	{
	if ( msg$ticket?$ciphertext )
		c$krb$new_ticket = md5_hash(msg$ticket$ciphertext);
	}

event krb_tgs_response(c: connection, msg: KDC_Response)
	{
	if ( msg$ticket?$ciphertext )
		c$krb$new_ticket = md5_hash(msg$ticket$ciphertext);
	}