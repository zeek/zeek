refine connection SMB_Conn += {

	function proc_smb1_transaction_secondary_request(header: SMB_Header, val: SMB1_transaction_secondary_request): bool
	%{
	if ( ! smb1_transaction_secondary_request )
		return false;

	RecordVal* args = new RecordVal(BifType::Record::SMB1::Trans_Sec_Args);
	args->Assign(0, new Val(${val.total_param_count}, TYPE_COUNT));
	args->Assign(1, new Val(${val.total_data_count}, TYPE_COUNT));
	args->Assign(2, new Val(${val.param_count}, TYPE_COUNT));
	args->Assign(3, new Val(${val.param_offset}, TYPE_COUNT));
	args->Assign(4, new Val(${val.param_displacement}, TYPE_COUNT));
	args->Assign(5, new Val(${val.data_count}, TYPE_COUNT));
	args->Assign(6, new Val(${val.data_offset}, TYPE_COUNT));
	args->Assign(7, new Val(${val.data_displacement}, TYPE_COUNT));

	StringVal* parameters = new StringVal(${val.parameters}.length(),
	                                      (const char*)${val.parameters}.data());
	StringVal* payload_str = nullptr;
	SMB1_transaction_data* payload = nullptr;

	if ( ${val.data_count} > 0 )
		{
		payload = ${val.data};
		}

	if ( payload )
		{
		switch ( payload->trans_type() ) {
		case SMB_PIPE:
			payload_str = new StringVal(${val.data_count}, (const char*)${val.data.pipe_data}.data());
			break;
		case SMB_UNKNOWN:
			payload_str = new StringVal(${val.data_count}, (const char*)${val.data.unknown}.data());
			break;
		default:
			payload_str = new StringVal(${val.data_count}, (const char*)${val.data.data}.data());
			break;
		}
		}

	if ( ! payload_str )
		{
		payload_str = new StringVal("");
		}

	BifEvent::generate_smb1_transaction_secondary_request(bro_analyzer(),
	                                                      bro_analyzer()->Conn(),
	                                                      BuildHeaderVal(header),
	                                                      args,
	                                                      parameters,
	                                                      payload_str);

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
