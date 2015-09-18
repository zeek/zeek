refine flow C12_22_Flow += {

	function proc_c12_22_message(msg: C12_22_PDU): bool
		%{
		RecordVal* rv = new RecordVal(BifType::Record::C12_22::APDU);
	
		for ( uint i = 0; i < ${msg.acse_args}->size(); ++i )
			{
			ACSE_Arg* element = (*msg->acse_args())[i];
			switch ( element->seq_meta()->index() )
				{
				case 2:
					rv->Assign(0, asn1_oid_to_val(element->data()->called_ap_title()));
					break;
				case 3:
					rv->Assign(1, asn1_integer_to_val(element->data()->called_ae_qualifier(), TYPE_COUNT));
					break;
				case 4:
					rv->Assign(2, asn1_integer_to_val(element->data()->called_ap_invocation_id(), TYPE_COUNT));
					break;
				case 5:
					rv->Assign(3, asn1_integer_to_val(element->data()->called_ae_invocation_id(), TYPE_COUNT));
					break;
				case 6:
					rv->Assign(4, asn1_oid_to_val(element->data()->calling_ap_title()));
					break;
				case 7:
					rv->Assign(5, asn1_integer_to_val(element->data()->calling_ae_qualifier(), TYPE_COUNT));
					break;
				case 8:
					rv->Assign(6, asn1_integer_to_val(element->data()->calling_ap_invocation_id(), TYPE_COUNT));
					break;
				case 9:
					rv->Assign(7, asn1_integer_to_val(element->data()->calling_ae_invocation_id(), TYPE_COUNT));
					break;
				case 11:
					rv->Assign(8, asn1_oid_to_val(element->data()->mechanism_name()));
					break;
				case 12:
					rv->Assign(9, bytestring_to_val(element->data()->calling_auth_value()));
					break;
				case 30:
					for ( uint j = 0; j < element->data()->user_information()->msgs()->size(); ++j )
						{
						C12_22_EPSEM_Data* epsem_element = (*element->data()->user_information()->msgs())[j];
						if ( ${epsem_element.msg.code} < 0x20)
							{
							BifEvent::generate_c12_22_epsem_response(connection()->bro_analyzer(), 
				                                connection()->bro_analyzer()->Conn(),
								rv->Ref(),
			        	                        ${epsem_element.msg.code});
							}
						else 
							{
							BifEvent::generate_c12_22_epsem_request(connection()->bro_analyzer(), 
				                                connection()->bro_analyzer()->Conn(),
								rv->Ref(),
			        	                        ${epsem_element.msg.code});
							}
						}
					break;
				default:
					break;
				}
			}
		BifEvent::generate_c12_22_end(connection()->bro_analyzer(), 
					      connection()->bro_analyzer()->Conn(),
					      rv->Ref());
		Unref(rv);

		return true;
		%}
};

refine typeattr C12_22_PDU += &let {
	proc: bool = $context.flow.proc_c12_22_message(this);
};

