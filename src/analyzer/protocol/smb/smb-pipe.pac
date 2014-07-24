# this won't work correctly yet, since sometimes the parameters
# field in the transaction takes up all of the data field

%include dce_rpc-protocol.pac

refine connection SMB_Conn += {
       function proc_smb_atsvc_job_add(val: AT_SVC_NetrJobAdd): bool
       		%{
		if ( smb_atsvc_job_add )
			{
			BifEvent::generate_smb_atsvc_job_add(bro_analyzer(), bro_analyzer()->Conn(), smb_string2stringval(${val.server.string}), smb_string2stringval(${val.command.string}));
			}
		return true;
		%}

       function proc_smb_atsvc_job_id(val: AT_SVC_JobID): bool
       		%{
		if ( smb_atsvc_job_id )
			{
			BifEvent::generate_smb_atsvc_job_id(bro_analyzer(), bro_analyzer()->Conn(), ${val.id}, ${val.status});
			}
		return true;
		%}

	function determine_pipe_msg_type(hdr: DCE_RPC_Header, opnum: uint8): uint8
		%{
		if ( !is_atsvc ) return 0;
		if ( ${hdr.PTYPE} == 0 && ${opnum} == 0 ) return 1;
		if ( ${hdr.PTYPE} == 2 && ${opnum} == 0 ) return 2;
		return 0;
		%}

};

type SMB_Pipe_message( unicode: bool, byte_count: uint16, sub_cmd: uint16 ) = record { 
	rpc      : DCE_RPC_Header;
	todo     : padding[6]; # These fields are currently missing from DCE/RPC for some reason.
	opnum    : uint8;
	pipe_type: case $context.connection.determine_pipe_msg_type(rpc, opnum) of {
		1       -> atsvc_request : AT_SVC_Request(unicode, opnum);
		2       -> atsvc_reply   : AT_SVC_Reply(unicode, opnum);
		default -> unknown       : bytestring &restofdata; 
	};
} &byteorder = littleendian;

type SMB_RAP_message( unicode: bool, byte_count: uint16 ) = record { 

	rap_code : uint16;
	param_desc : SMB_string(unicode, offsetof(param_desc) );
	data_desc : SMB_string(unicode, offsetof(data_desc) );
	data : bytestring &restofdata; 

} &byteorder = littleendian;

type AT_SVC_Request(unicode: bool, opnum: uint8) = record {
 	empty: padding[1];
	op: case opnum of {
		0 -> add: AT_SVC_NetrJobAdd(unicode);
		default -> unknown: bytestring &restofdata;
	};
};

type AT_SVC_String_Pointer(unicode: bool) = record {
	referent_id : uint32;
	max_count   : uint32;
	offset	    : uint32;
	actual_count: uint32;
	string	    : SMB_string(unicode, offsetof(string));
};

type AT_SVC_NetrJobAdd(unicode: bool) = record {
	server       : AT_SVC_String_Pointer(unicode);
	unknown      : padding[2];
	job_time     : uint32;
	days_of_month: uint32;
	days_of_week : uint8;
	flags        : uint8;
	unknown2     : padding[2];
	command      : AT_SVC_String_Pointer(unicode);
} &let {
	proc: bool = $context.connection.proc_smb_atsvc_job_add(this);
};

type AT_SVC_Reply(unicode: bool, opnum: uint16) = record {
	op: case opnum of {
		0 -> add: AT_SVC_JobID(unicode);
		default -> unknown: bytestring &restofdata;
	};
};

type AT_SVC_JobID(unicode: bool) = record {
	id: uint32;
	status: uint32;
} &let {
	proc: bool = $context.connection.proc_smb_atsvc_job_id(this);
};
