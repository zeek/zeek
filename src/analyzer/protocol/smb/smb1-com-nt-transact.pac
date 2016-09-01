refine connection SMB_Conn += {

	function proc_smb1_nt_transact_request(header: SMB_Header, val: SMB1_nt_transact_request): bool
		%{
		//printf("nt_transact_request\n");
		return true;
		%}

	function proc_smb1_nt_transact_response(header: SMB_Header, val: SMB1_nt_transact_response): bool
		%{
		//printf("nt_transact_response\n");
		return true;
		%}

};

# http://msdn.microsoft.com/en-us/library/ee441534.aspx
type SMB1_nt_transact_request(header: SMB_Header) = record {
	word_count          : uint8;
} &let {
	proc : bool = $context.connection.proc_smb1_nt_transact_request(header, this);
};

# http://msdn.microsoft.com/en-us/library/ee442112.aspx
type SMB1_nt_transact_response(header: SMB_Header) = record {
	word_count         : uint8;
} &let {
	proc : bool = $context.connection.proc_smb1_nt_transact_response(header, this);
};
