refine connection SMB_Conn += {

	function proc_smb1_transaction_secondary_request(header: SMB_Header, val: SMB1_transaction_secondary_request): bool
	%{
	if ( ! smb1_transaction_secondary_request )
		return false;

	auto args = make_intrusive<RecordVal>(BifType::Record::SMB1::Trans_Sec_Args);
	args->Assign(0, val_mgr->Count(${val.total_param_count}));
	args->Assign(1, val_mgr->Count(${val.total_data_count}));
	args->Assign(2, val_mgr->Count(${val.param_count}));
	args->Assign(3, val_mgr->Count(${val.param_offset}));
	args->Assign(4, val_mgr->Count(${val.param_displacement}));
	args->Assign(5, val_mgr->Count(${val.data_count}));
	args->Assign(6, val_mgr->Count(${val.data_offset}));
	args->Assign(7, val_mgr->Count(${val.data_displacement}));

	auto parameters = make_intrusive<StringVal>(${val.parameters}.length(),
	                                            (const char*)${val.parameters}.data());
	IntrusivePtr<StringVal> payload_str;
	SMB1_transaction_data* payload = nullptr;

	if ( ${val.data_count} > 0 )
		{
		payload = ${val.data};
		}

	if ( payload )
		{
		switch ( payload->trans_type() ) {
		case SMB_PIPE:
			payload_str = make_intrusive<StringVal>(${val.data_count}, (const char*)${val.data.pipe_data}.data());
			break;
		case SMB_UNKNOWN:
			payload_str = make_intrusive<StringVal>(${val.data_count}, (const char*)${val.data.unknown}.data());
			break;
		default:
			payload_str = make_intrusive<StringVal>(${val.data_count}, (const char*)${val.data.data}.data());
			break;
		}
		}

	if ( ! payload_str )
		{
		payload_str = val_mgr->EmptyString();
		}

	BifEvent::enqueue_smb1_transaction_secondary_request(bro_analyzer(),
	                                                     bro_analyzer()->Conn(),
	                                                     SMBHeaderVal(header),
	                                                     std::move(args),
	                                                     std::move(parameters),
	                                                     std::move(payload_str));

	return true;
	%}
};

type SMB1_transaction_secondary_request(header: SMB_Header) = record {
	word_count          : uint8;
	total_param_count   : uint16;
	total_data_count    : uint16;
	param_count         : uint16;
	param_offset        : uint16;
	param_displacement  : uint16;
	data_count          : uint16;
	data_offset         : uint16;
	data_displacement   : uint16;

	byte_count          : uint16;
	pad1                : padding to param_offset - SMB_Header_length;
	parameters          : bytestring &length = param_count;
	pad2                : padding to data_offset - SMB_Header_length;
	data                : SMB1_transaction_data(header, true, data_count, 0, SMB_UNKNOWN, false);
} &let {
  proc : bool = $context.connection.proc_smb1_transaction_secondary_request(header, this);
};
