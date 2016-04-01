
refine connection SMB_Conn += {
	%member{
		map<uint16,bool> tree_is_pipe_map;
	%}

	function get_tree_is_pipe(tree_id: uint16): bool
		%{
		if ( tree_is_pipe_map.count(tree_id) > 0 )
			return tree_is_pipe_map.at(tree_id);
		else
			return false;
		%}

	function set_tree_is_pipe(tree_id: uint16, is_pipe: bool): bool
		%{
		tree_is_pipe_map[tree_id] = is_pipe;
		return true;
		%}

	function forward_dce_rpc(pipe_data: bytestring, is_orig: bool): bool
		%{
		if ( dcerpc )
			dcerpc->DeliverStream(${pipe_data}.length(), ${pipe_data}.begin(), is_orig);
		return true;
		%}
};


#type SMB_Pipe_message(header: SMB_Header, byte_count: uint16) = record { 
#	rpc_header : DCE_RPC_Header;
#	rpc_body   : DCE_RPC_Body(rpc_header);
#	pipe_type: case $context.connection.determine_pipe_msg_type(rpc, opnum) of {
#		1       -> atsvc_request : AT_SVC_Request(unicode, opnum);
#		2       -> atsvc_reply   : AT_SVC_Reply(unicode, opnum);
#		default -> unknown       : bytestring &restofdata; 
#	};
#} &let {
#	proc: bool = $context.connection.proc_smb_pipe_message(this, header);
#} &byteorder = littleendian;
#
#type SMB_RAP_message(unicode: bool, byte_count: uint16) = record { 
#	rap_code   : uint16;
#	param_desc : SMB_string(unicode, offsetof(param_desc));
#	data_desc  : SMB_string(unicode, offsetof(data_desc));
#	data       : bytestring &restofdata; 
#} &byteorder = littleendian;

type AT_SVC_Request(unicode: bool, opnum: uint8) = record {
	empty: padding[1];
	op: case opnum of {
		0       -> add     : AT_SVC_NetrJobAdd(unicode);
		default -> unknown : bytestring &restofdata;
	};
};

type AT_SVC_String_Pointer(unicode: bool) = record {
	referent_id  : uint32;
	max_count    : uint32;
	offset       : uint32;
	actual_count : uint32;
	string       : SMB_string(unicode, offsetof(string));
};

type AT_SVC_NetrJobAdd(unicode: bool) = record {
	server        : AT_SVC_String_Pointer(unicode);
	unknown       : padding[2];
	job_time      : uint32;
	days_of_month : uint32;
	days_of_week  : uint8;
	flags         : uint8;
	unknown2      : padding[2];
	command       : AT_SVC_String_Pointer(unicode);
};

type AT_SVC_Reply(unicode: bool, opnum: uint16) = record {
	op: case opnum of {
		0       -> add:     AT_SVC_JobID(unicode);
		default -> unknown: bytestring &restofdata;
	};
};

type AT_SVC_JobID(unicode: bool) = record {
	id     : uint32;
	status : uint32;
};
