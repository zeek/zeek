# this won't work correctly yet, since sometimes the parameters
# field in the transaction takes up all of the data field

type SMB_Pipe_message( unicode: bool, byte_count: uint16, sub_cmd: uint16 ) = record { 

	# there's a problem with byte_count here, not sure why ... its
	# not the real length of the rest of the packet
	data : bytestring &restofdata; 

} &byteorder = littleendian;

type SMB_RAP_message( unicode: bool, byte_count: uint16 ) = record { 

	rap_code : uint16;
	param_desc : SMB_string(unicode, offsetof(param_desc) );
	data_desc : SMB_string(unicode, offsetof(data_desc) );
	data : bytestring &restofdata; 

} &byteorder = littleendian;
