%header{
RecordVal* proc_krb_kdc_options(const KRB_KDC_Options* opts);
RecordVal* proc_krb_kdc_req_arguments(KRB_KDC_REQ* msg, const BroAnalyzer bro_analyzer);

bool proc_error_arguments(RecordVal* rv, const std::vector<KRB_ERROR_Arg*>* args, int64 error_code);
%}

%code{
RecordVal* proc_krb_kdc_options(const KRB_KDC_Options* opts)
{
	RecordVal* rv = new RecordVal(BifType::Record::KRB::KDC_Options);

	rv->Assign(0, new Val(opts->forwardable(), TYPE_BOOL));
	rv->Assign(1, new Val(opts->forwarded(), TYPE_BOOL));
	rv->Assign(2, new Val(opts->proxiable(), TYPE_BOOL));
	rv->Assign(3, new Val(opts->proxy(), TYPE_BOOL));
	rv->Assign(4, new Val(opts->allow_postdate(), TYPE_BOOL));
	rv->Assign(5, new Val(opts->postdated(), TYPE_BOOL));
	rv->Assign(6, new Val(opts->renewable(), TYPE_BOOL));
	rv->Assign(7, new Val(opts->opt_hardware_auth(), TYPE_BOOL));
	rv->Assign(8, new Val(opts->disable_transited_check(), TYPE_BOOL));
	rv->Assign(9, new Val(opts->renewable_ok(), TYPE_BOOL));
	rv->Assign(10, new Val(opts->enc_tkt_in_skey(), TYPE_BOOL));
	rv->Assign(11, new Val(opts->renew(), TYPE_BOOL));
	rv->Assign(12, new Val(opts->validate(), TYPE_BOOL));

	return rv;
}

bool proc_error_arguments(RecordVal* rv, const std::vector<KRB_ERROR_Arg*>* args, int64 error_code )
{
	uint ctime_i = 0, ctime_usecs_i = 0, stime_i = 0, stime_usecs_i = 0;
	int64 ctime_usecs = 0, stime_usecs = 0;

	// We need to do a pass first, to see if we have microseconds for the timestamp values, which are optional

	for ( uint i = 0; i < args->size(); i++ )
		{
		switch ( (*args)[i]->seq_meta()->index() )
			{
			case 2:
				ctime_i = i;
				break;
			case 3:
				ctime_usecs_i = i;
				break;
			case 4:
				stime_i = i;
				break;
			case 5:
				stime_usecs_i = i;
				break;
			}
		}

	if ( ctime_usecs_i ) ctime_usecs = binary_to_int64((*args)[ctime_usecs_i]->args()->cusec()->encoding()->content());
	if ( ctime_i )	rv->Assign(2, GetTimeFromAsn1((*args)[ctime_i]->args()->ctime(), ctime_usecs));

	if ( stime_usecs_i ) stime_usecs = binary_to_int64((*args)[stime_usecs_i]->args()->susec()->encoding()->content());
	if ( stime_i ) rv->Assign(3, GetTimeFromAsn1((*args)[stime_i]->args()->stime(), stime_usecs));

	for ( uint i = 0; i < args->size(); i++ )
		{
		switch ( (*args)[i]->seq_meta()->index() )
			{
			case 0:
				rv->Assign(0, asn1_integer_to_val((*args)[i]->args()->pvno(), TYPE_COUNT));
				break;
			case 1:
				rv->Assign(1, asn1_integer_to_val((*args)[i]->args()->msg_type(), TYPE_COUNT));
				break;
			// ctime/stime handled above
			case 7:
				rv->Assign(5, bytestring_to_val((*args)[i]->args()->crealm()->encoding()->content()));
				break;
			case 8:
				rv->Assign(6, GetStringFromPrincipalName((*args)[i]->args()->cname()));
				break;
			case 9:
				rv->Assign(7, bytestring_to_val((*args)[i]->args()->realm()->encoding()->content()));
				break;
			case 10:
				rv->Assign(8, GetStringFromPrincipalName((*args)[i]->args()->sname()));
				break;
			case 11:
				rv->Assign(9, bytestring_to_val((*args)[i]->args()->e_text()->encoding()->content()));
				break;
			case 12:
				if ( error_code == KDC_ERR_PREAUTH_REQUIRED )
					rv->Assign(10, proc_padata((*args)[i]->args()->e_data()->padata(), NULL, true));
				break;
			default:
				break;
			}
		}

	return true;
}

RecordVal* proc_krb_kdc_req_arguments(KRB_KDC_REQ* msg, const BroAnalyzer bro_analyzer)
{
	RecordVal* rv = new RecordVal(BifType::Record::KRB::KDC_Request);

	rv->Assign(0, asn1_integer_to_val(msg->pvno()->data(), TYPE_COUNT));
	rv->Assign(1, asn1_integer_to_val(msg->msg_type()->data(), TYPE_COUNT));

	if ( msg->padata()->has_padata() )
		rv->Assign(2, proc_padata(msg->padata()->padata()->padata(), bro_analyzer, false));

	for ( uint i = 0; i < msg->body_args()->size(); ++i )
		{
		KRB_REQ_Arg* element = (*msg->body_args())[i];
		switch ( element->seq_meta()->index() )
			{
			case 0:
				rv->Assign(3, proc_krb_kdc_options(element->data()->options()));
				break;
			case 1:
				rv->Assign(4, GetStringFromPrincipalName(element->data()->principal()));
				break;
			case 2:
				rv->Assign(5, bytestring_to_val(element->data()->realm()->encoding()->content()));
				break;
			case 3:
				rv->Assign(6, GetStringFromPrincipalName(element->data()->sname()));
				break;
			case 4:
				rv->Assign(7, GetTimeFromAsn1(element->data()->from(), 0));
				break;
			case 5:
				rv->Assign(8, GetTimeFromAsn1(element->data()->till(), 0));
				break;
			case 6:
				rv->Assign(9, GetTimeFromAsn1(element->data()->rtime(), 0));
				break;
			case 7:
				rv->Assign(10, asn1_integer_to_val(element->data()->nonce(), TYPE_COUNT));
				break;
			case 8:
				if ( element->data()->etype()->data()->size() )
					rv->Assign(11, proc_cipher_list(element->data()->etype()));

				break;
			case 9:
				if ( element->data()->addrs()->addresses()->size() )
					rv->Assign(12, proc_host_address_list(element->data()->addrs()));

				break;
			case 10:
			// TODO
				break;
			case 11:
				if ( element->data()->addl_tkts()->tickets()->size() )
					rv->Assign(13, proc_tickets(element->data()->addl_tkts()));

				break;
			default:
				break;
			}
		}

	return rv;
}

%}

refine connection KRB_Conn += {

	function proc_krb_kdc_req(msg: KRB_KDC_REQ): bool
		%{
		bro_analyzer()->ProtocolConfirmation();
		if ( ( binary_to_int64(${msg.msg_type.data.content}) == 10 ) && ! krb_as_req )
			return false;

		if ( ( binary_to_int64(${msg.msg_type.data.content}) == 12 ) && ! krb_tgs_req )
			return false;		

		RecordVal* rv = proc_krb_kdc_req_arguments(${msg}, bro_analyzer());

		if ( ( binary_to_int64(${msg.msg_type.data.content}) == 10 ) )
			BifEvent::generate_krb_as_req(bro_analyzer(), bro_analyzer()->Conn(), rv);

		if ( ( binary_to_int64(${msg.msg_type.data.content}) == 12 ) )
			BifEvent::generate_krb_tgs_req(bro_analyzer(), bro_analyzer()->Conn(), rv);
				
		return true;
		%}

 	function proc_krb_kdc_rep(msg: KRB_KDC_REP): bool
		%{
		bro_analyzer()->ProtocolConfirmation();
		
		if ( ( binary_to_int64(${msg.msg_type.data.content}) == 11 ) && ! krb_as_rep )
			return false;

		if ( ( binary_to_int64(${msg.msg_type.data.content}) == 13 ) && ! krb_tgs_rep )
			return false;
		
		
		RecordVal* rv = new RecordVal(BifType::Record::KRB::KDC_Reply);

		rv->Assign(0, asn1_integer_to_val(${msg.pvno.data}, TYPE_COUNT));
		rv->Assign(1, asn1_integer_to_val(${msg.msg_type.data}, TYPE_COUNT));

		if ( ${msg.padata.has_padata} )
			rv->Assign(2, proc_padata(${msg.padata.padata.padata}, bro_analyzer(), false));

		rv->Assign(3, bytestring_to_val(${msg.client_realm.encoding.content}));
		rv->Assign(4, GetStringFromPrincipalName(${msg.client_name}));

		rv->Assign(5, proc_ticket(${msg.ticket}));

		if ( ( binary_to_int64(${msg.msg_type.data.content}) == 11 ) )
			BifEvent::generate_krb_as_rep(bro_analyzer(), bro_analyzer()->Conn(), rv);

		if ( ( binary_to_int64(${msg.msg_type.data.content}) == 13 ) )
			BifEvent::generate_krb_tgs_rep(bro_analyzer(), bro_analyzer()->Conn(), rv);
				
		return true;
   		%}
    
 	function proc_krb_error_msg(msg: KRB_ERROR_MSG): bool
		%{
		bro_analyzer()->ProtocolConfirmation();
		if ( krb_error )
			{
			RecordVal* rv = new RecordVal(BifType::Record::KRB::Error_Msg);
			proc_error_arguments(rv, ${msg.args1}, 0);
			rv->Assign(4, asn1_integer_to_val(${msg.error_code}, TYPE_COUNT));
			proc_error_arguments(rv, ${msg.args2}, binary_to_int64(${msg.error_code.encoding.content}));
			BifEvent::generate_krb_error(bro_analyzer(), bro_analyzer()->Conn(), rv);
			}
    		return true;
    		%}
    
 	function proc_krb_ap_req(msg: KRB_AP_REQ): bool
		%{
		bro_analyzer()->ProtocolConfirmation();
		if ( krb_ap_req )
			{
			RecordVal* rv = new RecordVal(BifType::Record::KRB::AP_Options);
			rv->Assign(0, new Val(${msg.ap_options.use_session_key}, TYPE_BOOL));
			rv->Assign(1, new Val(${msg.ap_options.mutual_required}, TYPE_BOOL));
			
			BifEvent::generate_krb_ap_req(bro_analyzer(), bro_analyzer()->Conn(), 
						      proc_ticket(${msg.ticket}), rv);
			}
   		return true;
   		%}
    
 	function proc_krb_ap_rep(msg: KRB_AP_REP): bool
		%{
		bro_analyzer()->ProtocolConfirmation();
		if ( krb_ap_rep )
			{
			BifEvent::generate_krb_ap_rep(bro_analyzer(), bro_analyzer()->Conn());
			}
   		return true;
   		%}
    
 	function proc_krb_safe_msg(msg: KRB_SAFE_MSG): bool
		%{
		bro_analyzer()->ProtocolConfirmation();
		// Not implemented
   		return true;
   		%}
    
 	function proc_krb_priv_msg(msg: KRB_PRIV_MSG): bool
		%{	
		bro_analyzer()->ProtocolConfirmation();
		if ( krb_priv )
			{
			BifEvent::generate_krb_priv(bro_analyzer(), bro_analyzer()->Conn());
			}
   		return true;
   		%}
    
 	function proc_krb_cred_msg(msg: KRB_CRED_MSG): bool
		%{
		bro_analyzer()->ProtocolConfirmation();
		if ( krb_cred )
			{
			BifEvent::generate_krb_cred(bro_analyzer(), bro_analyzer()->Conn(), proc_tickets(${msg.tickets}));
			}
   		return true;
   		%}
}


refine typeattr KRB_AS_REQ += &let {
	proc: bool = $context.connection.proc_krb_kdc_req(data);
};
    
refine typeattr KRB_TGS_REQ += &let {
	proc: bool = $context.connection.proc_krb_kdc_req(data);
};
    
refine typeattr KRB_AS_REP += &let {
	proc: bool = $context.connection.proc_krb_kdc_rep(data);
};
    
refine typeattr KRB_TGS_REP += &let {
	proc: bool = $context.connection.proc_krb_kdc_rep(data);
};
    
refine typeattr KRB_AP_REQ += &let {
	proc: bool = $context.connection.proc_krb_ap_req(this);
};
    
refine typeattr KRB_AP_REP += &let {
	proc: bool = $context.connection.proc_krb_ap_rep(this);
};
    
refine typeattr KRB_ERROR_MSG += &let {
	proc: bool = $context.connection.proc_krb_error_msg(this);
};
    
refine typeattr KRB_SAFE_MSG += &let {
	proc: bool = $context.connection.proc_krb_safe_msg(this);
};
    
refine typeattr KRB_PRIV_MSG += &let {
	proc: bool = $context.connection.proc_krb_priv_msg(this);
};
    
refine typeattr KRB_CRED_MSG += &let {
	proc: bool = $context.connection.proc_krb_cred_msg(this);
};
