# CIFS/SMB

# TODO:
# - Built support for unicode strings
# - Unicode as an implicit attribute (as byteorder)
# - &truncation_ok attribute for the last field of a record to deal with partial data

enum TransactionType {
	SMB_MAILSLOT_BROWSE, # \MAILSLOT\BROWSE - MS Browse Protocol
	SMB_MAILSLOT_LANMAN, # \MAILSLOT\LANMAN - deprecated cmds
	SMB_PIPE, # \PIPE\* named pipes?
	SMB_RAP, # \PIPE\LANMAN - remote administration protocol
	SMB_UNKNOWN, # there's probably lots of these
};

function extract_string(s: SMB_string) : const_bytestring
	%{
	int length = 0;

	char* buf;
	const char* sp;

	if( s->val_case_index() == 0 )
		{
		length = s->a()->size();
		buf = new char[ length ];

		for( int i = 0; i < length; i++)
			{
			unsigned char t = (*(s->a()))[i];
			buf[i] = t;
			}
		}
	else
		{
		length = s->u()->s()->size();
		buf = new char[ length ];

		for( int i = 0; i < length; i++)
			{
			unsigned short temp = (*(s->u()->s()))[i];
			buf[i] = temp & 0xff;
			}
		}

	return bytestring((uint8*) buf, length);
	%}

function determine_transaction_type(setup_count: int, name: SMB_string): TransactionType
	%{
	// This logic needs to be verified! the relationship between
	// setup_count and type is very unclear.
	if ( name == NULL )
		return SMB_UNKNOWN;

	if ( bytestring_caseprefix( extract_string(name),
			"\\PIPE\\LANMAN" ) )
		{
		return SMB_RAP;
		}
	else if ( bytestring_caseprefix( extract_string(name),
			"\\MAILSLOT\\LANMAN" ) )
		{
		return SMB_MAILSLOT_LANMAN;
		//return SMB_MAILSLOT_BROWSE;
		}
	else if ( bytestring_caseprefix( extract_string(name),
			"\\MAILSLOT\\NET\\NETLOGON" ) )
		{
		/* Don't really know what to do here, its got a Mailslot
		 * type but its a depricated packet format that handles
		 * old windows logon
		 */
		return SMB_UNKNOWN;
		}
	else if(setup_count == 2 ||
			bytestring_caseprefix( extract_string(name), "\\PIPE\\" ) )
		{
		return SMB_PIPE;
		}
	else if (setup_count == 3 ||
			bytestring_caseprefix( extract_string(name), "\\MAILSLOT\\" ) )
		{
		return SMB_MAILSLOT_BROWSE;
		}
	else
		return SMB_UNKNOWN;
	%}

function name_string(trans: SMB_transaction): SMB_string
	%{
	if( trans->trans_type() == 1 )
		return trans->name();
	else
		return NULL;
	%}


type SMB_dos_error = record {
	error_class	: uint8;
	reserved	: uint8;
	error		: uint16;
};

type SMB_error (err_status_type: int) = case err_status_type of {
	0 -> dos_error: SMB_dos_error;
	1 -> status: int32;
};

type SMB_header = record {
	protocol	: bytestring &length = 4;
	command		: uint8;
	status		: SMB_error(err_status_type);
	flags		: uint8;
	flags2		: uint16;
	pad		: padding[12];
	tid		: uint16;
	pid		: uint16;
	uid		: uint16;
	mid		: uint16;
} &let {
	err_status_type = (flags2 >> 14) & 1;
	unicode = (flags2 >> 15) & 1;
} &byteorder = littleendian;

# TODO: compute this as
# let smb_header_length = sizeof(SMB_header);
let smb_header_length = 32;

type SMB_body = record {
	word_count	: uint8;
	parameter_words : uint16[word_count];
	byte_count	: uint16;
	# buffer	: uint8[byte_count];
} &let {
	body_length = 1 + word_count * 2 + 2 + byte_count;
} &byteorder = littleendian;

type SMB_ascii_string		= uint8[] &until($element == 0);
type SMB_unicode_string(offset: int) = record {
	pad	: padding[offset & 1];
	s	: uint16[] &until($element == 0);
};

type SMB_string(unicode: bool, offset: int) = case unicode of {
	true	-> u: SMB_unicode_string(offset);
	false	-> a: SMB_ascii_string;
};

type SMB_time = record {
	two_seconds : uint16;
	minutes	: uint16;
	hours		: uint16;
} &byteorder = littleendian;

type SMB_date = record {
	day		: uint16;
	month		: uint16;
	year		: uint16;
} &byteorder = littleendian;

type SMB_andx = record {
	command		: uint8;
	reserved	: uint8;
	offset		: uint16;
} &refcount;

type SMB_generic_andx = record {
	word_count	: uint8;
	andx_u		: case word_count of {
		0	-> null : empty;
		default -> andx	: SMB_andx;
	};
	data		: bytestring &restofdata;
} &byteorder = littleendian;

type SMB_dialect = record {
	bufferformat	: uint8;	# must be 0x2
	dialectname	: SMB_ascii_string;
};

type SMB_negotiate = record {
	word_count	: uint8;	# must be 0
	byte_count	: uint16;
	dialects	: SMB_dialect[] &length = byte_count;
} &byteorder = littleendian;

type SMB_negotiate_response = record {
	word_count  : uint8; # should be 1
	dialect_index : uint16;
	byte_count  : uint16; # should be 0
} &byteorder = littleendian;

type SMB_negotiate_response_long(unicode: bool) = record {
	word_count  : uint8; # should be 13
	dialect_index : uint16;
	security_mode : uint16; # bit 0: 0=share 1=user, bit 1: 1=chalenge/response
	max_buffer_size : uint16;
	max_mpx_count : uint16;
	max_number_vcs : uint16;
	raw_mode : uint16;
	session_key : uint32;
	server_time : SMB_time;
	server_date : SMB_date;
	server_tz	: uint16;
	enc_key_len : uint16;
	reserved	: uint16; # must be 0
	byte_count : uint16;
	encryption_key : uint8[enc_key_len];
	primary_domain : SMB_string(unicode, offsetof(primary_domain));
} &byteorder = littleendian;

# pre NT LM 0.12
type SMB_setup_andx_basic(unicode: bool) = record {
	word_count	: uint8;
	andx		: SMB_andx;
	max_buffer_size : uint16;
	max_mpx_count	: uint16;
	vc_number	: uint16;
	session_key	: uint32;
	passwd_length	: uint8;
	reserved	: uint32;
	byte_count	: uint8;
	password	: uint8[passwd_length];
	name		: SMB_string(unicode, offsetof(name));
	domain		: SMB_string(unicode, offsetof(domain));
	native_os	: SMB_string(unicode, offsetof(native_os));
	native_lanman	: SMB_string(unicode, offsetof(native_lanman));
} &byteorder = littleendian;

type SMB_setup_andx_basic_response(unicode: bool) = record {
	word_count	: uint8;
	andx		: SMB_andx;
	action		: uint8;
	byte_count	: uint8;
	native_os	: SMB_string(unicode, offsetof(native_os));
	native_lanman	: SMB_string(unicode, offsetof(native_lanman));
	primary_domain	: SMB_string(unicode, offsetof(primary_domain));
} &byteorder = littleendian;

# NT LM 0.12 && CAP_EXTENDED_SECURITY
type SMB_setup_andx_ext(unicode: bool) = record {
	word_count	: uint8;
	andx		: SMB_andx;
	max_buffer_size : uint16;
	max_mpx_count	: uint16;
	vc_number	: uint16;
	session_key	: uint32;
	security_length : uint8;
	reserved	: uint32;
	capabilities	: uint32;
	byte_count	: uint8;
	security_blob	: uint8[security_length];
	native_os	: SMB_string(unicode, offsetof(native_os));
	native_lanman	: SMB_string(unicode, offsetof(native_lanman));
} &byteorder = littleendian;

type SMB_setup_andx_ext_response(unicode: bool) = record {
	word_count	: uint8;
	andx		: SMB_andx;
	action		: uint8;
	security_length : uint8;
	byte_count	: uint8;
	security_blob	: uint8[security_length];
	native_os	: SMB_string(unicode, offsetof(native_os));
	native_lanman	: SMB_string(unicode, offsetof(native_lanman));
	primary_domain	: SMB_string(unicode, offsetof(primary_domain));
} &byteorder = littleendian;

type SMB_logoff_andx(unicode: bool) = record {
	word_count	: uint8;
	andx		: SMB_andx;
	byte_count	: uint16;
} &byteorder = littleendian;

type SMB_tree_connect_andx(unicode: bool) = record {
	word_count	: uint8;
	andx		: SMB_andx;
	flags		: uint16;
	password_length	: uint16;
	byte_count	: uint16;
	password	: uint8[password_length];
	path		: SMB_string(unicode, offsetof(path));
	service		: SMB_ascii_string;
} &byteorder = littleendian;

type SMB_close(unicode: bool) = record {
	word_count  : uint8;
	fid		: uint16;
	time		: SMB_time;
	byte_count  : uint16;
} &byteorder = littleendian;

type SMB_tree_disconnect(unicode: bool) = record {
	word_count	: uint8;
	byte_count	: uint16;
} &byteorder = littleendian;

type SMB_nt_create_andx(unicode: bool) = record {
	word_count	: uint8;
	andx		: SMB_andx;
	reserved	: uint8;
	name_length	: uint16;
	flags		: uint32;
	rest_words	: uint8[word_count * 2 - 11];
	byte_count	: uint16;
	name		: SMB_string(unicode, offsetof(name));
} &byteorder = littleendian;

type SMB_read_andx = record {
	word_count	: uint8;
	andx		: SMB_andx;
	fid		: uint16;
	offset		: uint32;
	max_count	: uint16;
	min_count	: uint16;
	max_count_high	: uint16;
	remaining	: uint16;
	offset_high_u	: case word_count of {
		12-> offset_high : uint32;
		10-> null : empty;
	};
	byte_count	: uint16;
} &byteorder = littleendian;

type SMB_read_andx_response = record {
	word_count	: uint8;
	andx		: SMB_andx;
	remaining	: uint16;
	data_compact	: uint16;
	reserved	: uint16;
	data_len	: uint16;
	data_offset	: uint16;
	data_len_high	: uint16;
	reserved2	: uint16[4];
	byte_count	: uint16;
	pad		: padding[padding_length];
	data		: bytestring &length = data_length;
	# Chris: the length here is causing problems - could we be having
	# issues with the packet format or is the data_length just not
	# right. The problem is that the padding isn't always filled right,
	# espeically when its not the first command in the packet.
	#data		: bytestring &restofdata;
} &let {
	data_length = data_len_high * 0x10000 + data_len;
	padding_length = byte_count - data_length;
} &byteorder = littleendian;

type SMB_write_andx = record {
	word_count	: uint8;
	andx		: SMB_andx;
	fid		: uint16;
	offset		: uint32;
	reserved	: uint32;
	write_mode	: uint16;
	remaining	: uint16;
	data_len_high	: uint16;
	data_len	: uint16;
	data_offset	: uint16;
	rest_words	: uint8[word_count * 2 - offsetof(rest_words) + 1];
	byte_count	: uint16;
	pad		: padding to data_offset - smb_header_length;
	data		: bytestring &length = data_length;
} &let {
	data_length = data_len_high * 0x10000 + data_len;
} &byteorder = littleendian;

type SMB_write_andx_response = record {
	word_count	: uint8;
	andx		: SMB_andx;
	count		: uint16;	# written bytes
	remaining	: uint16;
	reserved	: uint32;
	byte_count	: uint16;
} &byteorder = littleendian;

type SMB_transaction_data(unicode: bool, count: uint16, sub_cmd: uint16,
				trans_type: TransactionType ) = case trans_type of {

	SMB_MAILSLOT_BROWSE -> mailslot : SMB_MailSlot_message(unicode, count);
	SMB_MAILSLOT_LANMAN -> lanman : SMB_MailSlot_message(unicode, count);
	SMB_RAP -> rap	: SMB_Pipe_message(unicode, count, sub_cmd);
	SMB_PIPE -> pipe : SMB_Pipe_message(unicode, count, sub_cmd);
	SMB_UNKNOWN -> unknown : bytestring &restofdata;
	default -> data : bytestring &restofdata;

};

type SMB_transaction(trans_type: int, unicode: bool) = record {
	word_count		: uint8;
	total_param_count	: uint16;
	total_data_count	: uint16;
	max_param_count		: uint16;
	max_data_count		: uint16;
	max_setup_count		: uint8;
	reserved		: uint8;
	flags			: uint16;
	timeout			: uint32;
	reserved2		: uint16;
	param_count		: uint16;
	param_offset	: uint16;
	data_count		: uint16;
	data_offset		: uint16;
	setup_count		: uint8;
	reserved3		: uint8;
	setup			: uint16[setup_count];
	byte_count		: uint16;
	name_u			: case trans_type of {
		1 -> name: SMB_string(unicode, offsetof(name_u));
		2 -> null: empty;
		};
	pad0			: padding to param_offset - smb_header_length;
	parameters		: bytestring &length = param_count;
	pad1			: padding to data_offset - smb_header_length;
	data			: SMB_transaction_data(unicode, data_count, sub_cmd,
						determine_transaction_type( setup_count, name_string( this )));
} &let {
	# does this work?
	sub_cmd : uint16 = setup_count ? setup[0] : 0;

} &byteorder = littleendian;

type SMB_transaction_secondary(unicode: bool) = record {
	word_count		: uint8;
	total_param_count	: uint16;
	total_data_count	: uint16;
	param_count		: uint16;
	param_offset		: uint16;
	param_displacement	: uint16;
	data_count		: uint16;
	data_offset		: uint16;
	data_displacement	: uint16;
	fid			: uint16;
	byte_count		: uint16;
	pad0			: padding to param_offset - smb_header_length;
	parameters		: bytestring &length = param_count;
	pad1			: padding to data_offset - smb_header_length;
	data			: SMB_transaction_data(unicode, data_count, 0, SMB_UNKNOWN);
} &byteorder = littleendian;

type SMB_transaction_response(unicode: bool) = record {
	word_count		: uint8;
	total_param_count	: uint16;
	total_data_count	: uint16;
	reserved		: uint16;
	param_count		: uint16;
	param_offset		: uint16;
	param_displacement	: uint16;
	data_count		: uint16;
	data_offset		: uint16;
	data_displacement	: uint16;
	setup_count		: uint8;
	reserved2		: uint8;
	setup			: uint16[setup_count];
	byte_count		: uint16;
	pad0			: padding to param_offset - smb_header_length;
	parameters		: bytestring &length = param_count;
	pad1			: padding to data_offset - smb_header_length;
	data			: SMB_transaction_data(unicode, data_count, 0, SMB_UNKNOWN);
} &byteorder = littleendian;

type SMB_get_dfs_referral(unicode: bool) = record {
	max_referral_level	: uint16;
	file_name		: SMB_string(unicode, offsetof(file_name));
} &byteorder = littleendian;
