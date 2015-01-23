%extern{
#include "file_analysis/Manager.h"
%}


%header{
Val* GetTimeFromAsn1(const KRB_Time* atime);
Val* GetTimeFromAsn1(StringVal* atime);

Val* GetStringFromPrincipalName(const KRB_Principal_Name* pname);

Val* asn1_integer_to_val(const ASN1Encoding* i, TypeTag t);
Val* asn1_integer_to_val(const ASN1Integer* i, TypeTag t);

RecordVal* proc_krb_kdc_options(const KRB_KDC_Options* opts);
%}

%code{
Val* GetTimeFromAsn1(const KRB_Time* atime)
	{
	return GetTimeFromAsn1(bytestring_to_val(atime->time()));
	}

Val* GetTimeFromAsn1(StringVal* atime)
	{
	time_t lResult = 0;

	char lBuffer[17];
	char* pBuffer = lBuffer;

	size_t lTimeLength = atime->Len();
	char * pString = (char *) atime->Bytes();
	
	if ( lTimeLength != 15 && lTimeLength != 17 )
		return 0;

	if (lTimeLength == 17 )
		pString = pString + 2;
		
	memcpy(pBuffer, pString, 15);
	*(pBuffer+15) = '\0';

	tm lTime;
	lTime.tm_sec  = ((lBuffer[12] - '0') * 10) + (lBuffer[13] - '0');
	lTime.tm_min  = ((lBuffer[10] - '0') * 10) + (lBuffer[11] - '0');
	lTime.tm_hour = ((lBuffer[8] - '0') * 10) + (lBuffer[9] - '0');
	lTime.tm_mday = ((lBuffer[6] - '0') * 10) + (lBuffer[7] - '0');
	lTime.tm_mon  = (((lBuffer[4] - '0') * 10) + (lBuffer[5] - '0')) - 1;
	lTime.tm_year = ((lBuffer[0] - '0') * 1000) + ((lBuffer[1] - '0') * 100) + ((lBuffer[2] - '0') * 10) + (lBuffer[3] - '0') - 1900;

	lTime.tm_wday = 0;
	lTime.tm_yday = 0;
	lTime.tm_isdst = 0;

	lResult = timegm(&lTime);

	if ( !lResult )
		lResult = 0;

	return new Val(double(lResult), TYPE_TIME);
	}

Val* GetStringFromPrincipalName(const KRB_Principal_Name* pname)
{
	if ( pname->data()->size() == 1 )
 		return bytestring_to_val(pname->data()[0][0]->encoding()->content());
 	if ( pname->data()->size() == 2 )
 		return new StringVal(fmt("%s/%s", (char *) pname->data()[0][0]->encoding()->content().begin(), (char *)pname->data()[0][1]->encoding()->content().begin()));

	return new StringVal("unknown");
}

Val* asn1_integer_to_val(const ASN1Integer* i, TypeTag t)
{
	return asn1_integer_to_val(i->encoding(), t);
}

Val* asn1_integer_to_val(const ASN1Encoding* i, TypeTag t)
{
	return new Val(binary_to_int64(i->content()), t);
}

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

%}

refine connection KRB_Conn += {

	function proc_krb_kdc_req(msg: KRB_KDC_REQ): bool
		%{
		bro_analyzer()->ProtocolConfirmation();
		if ( ( binary_to_int64(${msg.msg_type.data.content}) == 10 ) && ! krb_as_req )
			return false;

		if ( ( binary_to_int64(${msg.msg_type.data.content}) == 12 ) && ! krb_tgs_req )
			return false;
		
		
		RecordVal* rv = new RecordVal(BifType::Record::KRB::KDC_Request);

		rv->Assign(0, asn1_integer_to_val(${msg.pvno.data}, TYPE_COUNT));
		rv->Assign(1, asn1_integer_to_val(${msg.msg_type.data}, TYPE_COUNT));

		if ( ${msg.has_padata} )
			{
			VectorVal* padata = new VectorVal(internal_type("KRB::Type_Value_Vector")->AsVectorType());

			for ( uint i = 0; i < ${msg.padata.padata_elems}->size(); ++i)
				{
				switch( ${msg.padata.padata_elems[i].data_type} )
					{
					case 1:
						// will be generated as separate event
						break;
					case 3:
						{
						RecordVal * type_val = new RecordVal(BifType::Record::KRB::Type_Value);
						type_val->Assign(0, new Val(${msg.padata.padata_elems[i].data_type}, TYPE_COUNT));
						type_val->Assign(1, bytestring_to_val(${msg.padata.padata_elems[i].pa_data_element.pa_pw_salt.encoding.content}));
						padata->Assign(padata->Size(), type_val);
						break;
						}
					case 16:
						{
						const bytestring& cert = ${msg.padata.padata_elems[i].pa_data_element.pa_pk_as_req.cert};

						ODesc common;
						common.AddRaw("Analyzer::ANALYZER_KRB");
						common.Add(bro_analyzer()->Conn()->StartTime());
						common.AddRaw("T", 1);
						bro_analyzer()->Conn()->IDString(&common);

						ODesc file_handle;
						file_handle.Add(common.Description());
						file_handle.Add(0);

						string file_id = file_mgr->HashHandle(file_handle.Description());

						file_mgr->DataIn(reinterpret_cast<const u_char*>(cert.data()),
			                 cert.length(), bro_analyzer()->GetAnalyzerTag(),
			                 bro_analyzer()->Conn(), true, file_id);
						file_mgr->EndOfFile(file_id);

						break;
						}
					default:
						{
						if ( ${msg.padata.padata_elems[i].pa_data_element.unknown}.length() )
							{
							RecordVal * type_val = new RecordVal(BifType::Record::KRB::Type_Value);
							type_val->Assign(0, new Val(${msg.padata.padata_elems[i].data_type}, TYPE_COUNT));
							type_val->Assign(1, bytestring_to_val(${msg.padata.padata_elems[i].pa_data_element.unknown}));
							padata->Assign(padata->Size(), type_val);
							}
						break;
						}
					}
				}
			rv->Assign(2, padata);
			}

		for ( uint i = 0; i < ${msg.body.args}->size(); ++i )
			{
			switch ( ${msg.body.args[i].seq_meta.index} )
				{
				case 0:
					rv->Assign(3, proc_krb_kdc_options(${msg.body.args[i].data.options}));
					break;
				case 1:
					rv->Assign(4, GetStringFromPrincipalName(${msg.body.args[i].data.principal}));
					break;
				case 2:
					rv->Assign(5, bytestring_to_val(${msg.body.args[i].data.realm.encoding.content}));
					break;
				case 3:
					rv->Assign(6, GetStringFromPrincipalName(${msg.body.args[i].data.sname}));
					break;
				case 4:
					rv->Assign(7, GetTimeFromAsn1(${msg.body.args[i].data.from}));
					break;
				case 5:
					rv->Assign(8, GetTimeFromAsn1(${msg.body.args[i].data.till}));
					break;
				case 6:
					rv->Assign(9, GetTimeFromAsn1(${msg.body.args[i].data.rtime}));
					break;
				case 7:
					rv->Assign(10, asn1_integer_to_val(${msg.body.args[i].data.nonce}, TYPE_COUNT));
					break;
				case 8:
					if ( ${msg.body.args[i].data.etype.data}->size() )
						{
						VectorVal* ciphers = new VectorVal(internal_type("index_vec")->AsVectorType());

						for ( uint j = 0; j < ${msg.body.args[i].data.etype.data}->size(); ++j )
							ciphers->Assign(ciphers->Size(), asn1_integer_to_val(${msg.body.args[i].data.etype.data[j]}, TYPE_COUNT));

						rv->Assign(11, ciphers);
						}
					break;
				case 9:
					if ( ${msg.body.args[i].data.addrs.addresses}->size() )
						{
						VectorVal* addrs = new VectorVal(internal_type("KRB::Host_Address_Vector")->AsVectorType());
						
						for ( uint j = 0; j < ${msg.body.args[i].data.addrs.addresses}->size(); ++j )
							{
							RecordVal* addr = new RecordVal(BifType::Record::KRB::Host_Address);
							switch ( binary_to_int64(${msg.body.args[i].data.addrs.addresses[j].addr_type.encoding.content}) )
								{
								case 2:
								addr->Assign(0, new AddrVal(IPAddr(IPv4, (const uint32_t*) c_str(${msg.body.args[i].data.addrs.addresses[j].address.data.content}), IPAddr::Network)));
								break;
								case 24:
								addr->Assign(0, new AddrVal(IPAddr(IPv6, (const uint32_t*) c_str(${msg.body.args[i].data.addrs.addresses[j].address.data.content}), IPAddr::Network)));
								break;
								case 20:
								addr->Assign(1, bytestring_to_val(${msg.body.args[i].data.addrs.addresses[j].address.data.content}));
								break;
								default:
								RecordVal* unk = new RecordVal(BifType::Record::KRB::Type_Value);
								unk->Assign(0, asn1_integer_to_val(${msg.body.args[i].data.addrs.addresses[j].addr_type}, TYPE_COUNT));
								unk->Assign(1, bytestring_to_val(${msg.body.args[i].data.addrs.addresses[j].address.data.content}));
								addr->Assign(2, unk);
								break;
								}
							addrs->Assign(addrs->Size(), addr);
							}

						rv->Assign(12, addrs);
						}
					break;
				case 10:
				// TODO
				break;
				case 11:
					if ( ${msg.body.args[i].data.addl_tkts.tickets}->size() )
						{
						VectorVal* tickets = new VectorVal(internal_type("KRB::Ticket_Vector")->AsVectorType());

						for ( uint j = 0; j < ${msg.body.args[i].data.addl_tkts.tickets}->size(); ++j )
							{
							RecordVal* ticket = new RecordVal(BifType::Record::KRB::Ticket);

							ticket->Assign(0, asn1_integer_to_val(${msg.body.args[i].data.addl_tkts.tickets[j].tkt_vno.data}, TYPE_COUNT));
							ticket->Assign(1, bytestring_to_val(${msg.body.args[i].data.addl_tkts.tickets[j].realm.data.content}));
							ticket->Assign(2, GetStringFromPrincipalName(${msg.body.args[i].data.addl_tkts.tickets[j].sname}));
							ticket->Assign(3, asn1_integer_to_val(${msg.body.args[i].data.addl_tkts.tickets[j].enc_part.etype.data}, TYPE_COUNT));
							tickets->Assign(tickets->Size(), ticket);
							}
						rv->Assign(13, tickets);
						}
					break;
				default:
					break;
				}
			}

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

		if ( ${msg.has_padata} )
			{
			VectorVal* padata = new VectorVal(internal_type("KRB::Type_Value_Vector")->AsVectorType());

			for ( uint i = 0; i < ${msg.padata.padata_elems}->size(); ++i)
				{
				switch( ${msg.padata.padata_elems[i].data_type} )
					{
					case 1:
						// will be generated as separate event
						break;
					case 2:
						// encrypted timestamp is unreadable
						break;
					case 3:
						{
						RecordVal * type_val = new RecordVal(BifType::Record::KRB::Type_Value);
						type_val->Assign(0, new Val(${msg.padata.padata_elems[i].data_type}, TYPE_COUNT));
						type_val->Assign(1, bytestring_to_val(${msg.padata.padata_elems[i].pa_data_element.pa_pw_salt.encoding.content}));
						padata->Assign(padata->Size(), type_val);
						break;
						}
					case 17:
						{
						const bytestring& cert = ${msg.padata.padata_elems[i].pa_data_element.pa_pk_as_rep.cert};
							
						ODesc common;
						common.AddRaw("Analyzer::ANALYZER_KRB");
						common.Add(bro_analyzer()->Conn()->StartTime());
						common.AddRaw("F", 1);
						bro_analyzer()->Conn()->IDString(&common);

						ODesc file_handle;
						file_handle.Add(common.Description());
						file_handle.Add(1);

						string file_id = file_mgr->HashHandle(file_handle.Description());

						file_mgr->DataIn(reinterpret_cast<const u_char*>(cert.data()),
			                 cert.length(), bro_analyzer()->GetAnalyzerTag(),
			                 bro_analyzer()->Conn(), false, file_id);
						file_mgr->EndOfFile(file_id);

						break;
						}
					default:
						{
						RecordVal * type_val = new RecordVal(BifType::Record::KRB::Type_Value);
						type_val->Assign(0, new Val(${msg.padata.padata_elems[i].data_type}, TYPE_COUNT));
						type_val->Assign(1, bytestring_to_val(${msg.padata.padata_elems[i].pa_data_element.unknown}));
						padata->Assign(padata->Size(), type_val);
						break;
						}
					}
				}
			rv->Assign(2, padata);
			}

		rv->Assign(3, bytestring_to_val(${msg.client_realm.encoding.content}));
		rv->Assign(4, GetStringFromPrincipalName(${msg.client_name}));

		RecordVal* ticket = new RecordVal(BifType::Record::KRB::Ticket);

		ticket->Assign(0, asn1_integer_to_val(${msg.ticket.tkt_vno.data}, TYPE_COUNT));
		ticket->Assign(1, bytestring_to_val(${msg.ticket.realm.data.content}));
		ticket->Assign(2, GetStringFromPrincipalName(${msg.ticket.sname}));
		ticket->Assign(3, asn1_integer_to_val(${msg.ticket.enc_part.etype.data}, TYPE_COUNT));

		rv->Assign(5, ticket);

		if ( ( binary_to_int64(${msg.msg_type.data.content}) == 11 ) )
			BifEvent::generate_krb_as_rep(bro_analyzer(), bro_analyzer()->Conn(), rv);

		if ( ( binary_to_int64(${msg.msg_type.data.content}) == 13 ) )
			BifEvent::generate_krb_tgs_rep(bro_analyzer(), bro_analyzer()->Conn(), rv);
				
		return true;
   		%}
    
 	function proc_krb_ap_req(msg: KRB_AP_REQ): bool
		%{
		bro_analyzer()->ProtocolConfirmation();
		// Not implemented
   		return true;
   		%}
    
 	function proc_krb_ap_rep(msg: KRB_AP_REP): bool
		%{
		bro_analyzer()->ProtocolConfirmation();
		// Not implemented
   		return true;
   		%}
    
 	function proc_krb_error_msg(msg: KRB_ERROR_MSG): bool
		%{
		bro_analyzer()->ProtocolConfirmation();
		if ( krb_error )
			{
			RecordVal* rv = new RecordVal(BifType::Record::KRB::Error_Msg);
			rv->Assign(0, asn1_integer_to_val(${msg.pvno.data}, TYPE_COUNT));
			rv->Assign(1, asn1_integer_to_val(${msg.msg_type.data}, TYPE_COUNT));
			if ( ${msg.has_ctime} )
				rv->Assign(2, GetTimeFromAsn1(bytestring_to_val(${msg.ctime})));

			// TODO: if ( ${msg.has_cusec} )
				
			rv->Assign(3, GetTimeFromAsn1(bytestring_to_val(${msg.stime})));
			// TODO: ${msg.susec}

			
			rv->Assign(4, asn1_integer_to_val(${msg.error_code.data}, TYPE_COUNT));
			
			for ( uint i = 0; i < ${msg.args}->size(); i++ )
				{
				switch ( ${msg.args[i].seq_meta.index} )
					{
					case 7:
						rv->Assign(5, bytestring_to_val(${msg.args[i].args.crealm.encoding.content}));
						break;
					case 8:
						rv->Assign(6, GetStringFromPrincipalName(${msg.args[i].args.cname}));
						break;
					case 9:
						rv->Assign(7, bytestring_to_val(${msg.args[i].args.realm.encoding.content}));
						break;
					case 10:
						rv->Assign(8, GetStringFromPrincipalName(${msg.args[i].args.sname}));
						break;
					case 11:
						rv->Assign(9, bytestring_to_val(${msg.args[i].args.e_text.encoding.content}));
						break;
					case 12:
						// if ( ${msg.error_code.data.content}[0] == 25 )
						// 	{
						// 	VectorVal* padata = new VectorVal(internal_type("KRB::Type_Value_Vector")->AsVectorType());

						// 	for ( uint j = 0; j < ${msg.args[i].args.e_data.padata.padata_elems}->size(); ++j)
						// 		{
						// 		switch( ${msg.args[i].args.e_data.padata.padata_elems[j].data_type} )
						// 			{
						// 		case 1:
						// 			// will be generated as separate event
						// 			break;
						// 		case 3:
						// 			{
						// 			RecordVal * type_val = new RecordVal(BifType::Record::KRB::Type_Value);
						// 			type_val->Assign(0, new Val(${msg.args[i].args.e_data.padata.padata_elems[j].data_type}, TYPE_COUNT));
						// 			type_val->Assign(1, bytestring_to_val(${msg.args[i].args.e_data.padata.padata_elems[j].pa_data_element.pa_pw_salt.encoding.content}));
						// 			padata->Assign(padata->Size(), type_val);
						// 			break;
						// 			}
						// 		default:
						// 			{
						// 			if ( ${msg.args[i].args.e_data.padata.padata_elems[j].pa_data_element.unknown}.length() )
						// 				{
						// 				RecordVal * type_val = new RecordVal(BifType::Record::KRB::Type_Value);
						// 				type_val->Assign(0, new Val(${msg.args[i].args.e_data.padata.padata_elems[j].data_type}, TYPE_COUNT));
						// 				type_val->Assign(1, bytestring_to_val(${msg.args[i].args.e_data.padata.padata_elems[j].pa_data_element.unknown}));
						// 				padata->Assign(padata->Size(), type_val);
						// 				}
						// 			break;
						// 			}
						// 			}
						// 		}
						// 	rv->Assign(10, padata);
						// 	}
						break;
					default:
						break;
					}
				}
				BifEvent::generate_krb_error(bro_analyzer(), bro_analyzer()->Conn(), rv);
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
		// Not implemented
   		return true;
   		%}
    
 	function proc_krb_cred_msg(msg: KRB_CRED_MSG): bool
		%{
		bro_analyzer()->ProtocolConfirmation();
		// Not implemented
   		return true;
   		%}

	function debug_req_arg(msg: KRB_REQ_Arg_Data): bool
		%{
		printf("KRB_REQ_Arg index=%d\n", ${msg.index});
		return true;
		%}

	function debug_asn1_encoding_meta(msg: ASN1EncodingMeta): bool
		%{
		printf("ASN1 Element tag=%x, length=%d\n", ${msg.tag}, ${msg.length});
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
    
#refine typeattr KRB_REQ_Arg_Data += &let {
#	proc: bool = $context.connection.debug_req_arg(this);
#};

#refine typeattr ASN1EncodingMeta += &let {
#	proc: bool = $context.connection.debug_asn1_encoding_meta(this);
#};

