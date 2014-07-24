# Packet Documentation
# http://msdn.microsoft.com/en-us/library/dd305039.aspx

type TDS_PDU = record {
	header:  TDS_Header;
	message: TDS_Message(header);
} &byteorder=bigendian &length=header.len;

type TDS_Header = record {
	message_type: uint8; # http://msdn.microsoft.com/en-us/library/dd304214.aspx
	status: uint8;       # http://msdn.microsoft.com/en-us/library/dd358342.aspx
	len: uint16;
	spid: uint16;        # process id.  server needs to send it.  client can too.
	packet_id: uint8;
	window: uint8;       # should be 0
} &let {
	eom: bool = ((status>>1) & 1) == 1;
};

type TDS_Message(h: TDS_Header) = case h.message_type of {
	0x01    -> sql_batch: SQL_Batch(h);
	# 0x04    -> token_stream: TDS_Token[];
	default -> blah : bytestring &transient &restofdata;
};

	function proc_testing(a: SQL_Batch): bool
		%{
		printf("%.6f query: %s\n", network_time(), smb2_string2stringval(${a.query})->CheckString());

		return true;
		%}

type SQL_Batch(h: TDS_Header) = record {
	#total_len            : uint32;
	#
	#header_len           : uint32;
	#header_type          : uint16;
	#trans_descriptor     : uint64;
	#outstanding_requests : uint32;

	#query: SMB2_string(total_len-header_len);
	query: SMB2_string(h.len-8);
} &let {
	proc: bool = proc_testing(this);
};


type TDS_Token = record {
	token_type: uint8;
	token: case token_type of {
		0xE3    -> envchange : TDS_Token_EnvChange;
		0xAB    -> info      : TDS_Token_Info;
		default -> blah      : bytestring &transient &restofdata;
	};
};


type TDS_Token_EnvChange = record {
	len: uint16;
	envchange_type: uint8;
	new_value: bytestring &length=len-2;
	#tab: RE/\x09/;
	#old_value: bytestring &length=
};

type TDS_Token_Info = record {
	
};

