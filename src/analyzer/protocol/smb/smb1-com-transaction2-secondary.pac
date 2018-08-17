refine connection SMB_Conn += {

	function proc_smb1_transaction2_secondary_request(header: SMB_Header, val: SMB1_transaction2_secondary_request): bool
	%{
	if ( ! smb1_transaction2_secondary_request )
		return false;

	RecordVal* args = new RecordVal(BifType::Record::SMB1::Trans2_Sec_Args);
	args->Assign(0, new Val(${val.total_param_count}, TYPE_COUNT));
	args->Assign(1, new Val(${val.total_data_count}, TYPE_COUNT));
	args->Assign(2, new Val(${val.param_count}, TYPE_COUNT));
	args->Assign(3, new Val(${val.param_offset}, TYPE_COUNT));
	args->Assign(4, new Val(${val.param_displacement}, TYPE_COUNT));
	args->Assign(5, new Val(${val.data_count}, TYPE_COUNT));
	args->Assign(6, new Val(${val.data_offset}, TYPE_COUNT));
	args->Assign(7, new Val(${val.data_displacement}, TYPE_COUNT));
	args->Assign(8, new Val(${val.FID}, TYPE_COUNT));

	StringVal* parameters = new StringVal(${val.parameters}.length(), (const char*)${val.parameters}.data());
	StringVal* payload = new StringVal(${val.data}.length(), (const char*)${val.data}.data());

	BifEvent::generate_smb1_transaction2_secondary_request(bro_analyzer(),
	                                                       bro_analyzer()->Conn(),
	                                                       BuildHeaderVal(header),
	                                                       args,
	                                                       parameters,
	                                                       payload);

	return true;
	%}
};

type SMB1_transaction2_secondary_request(header: SMB_Header) = record {
	word_count          : uint8;
	total_param_count   : uint16;
	total_data_count    : uint16;
	param_count         : uint16;
	param_offset        : uint16;
	param_displacement  : uint16;
	data_count          : uint16;
	data_offset         : uint16;
	data_displacement   : uint16;
	FID                 : uint16;

	byte_count          : uint16;
	pad1                : padding to (param_offset - SMB_Header_length);
	parameters          : bytestring &length = param_count;
	pad2                : padding to (data_offset - SMB_Header_length);
	data                : bytestring &length=data_count;
} &let {
	proc : bool = $context.connection.proc_smb1_transaction2_secondary_request(header, this);
};
