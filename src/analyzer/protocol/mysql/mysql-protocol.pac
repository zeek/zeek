# See the file "COPYING" in the main distribution directory for copyright.
#
# All information is from the MySQL internals documentation at:
# <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>
#

# Basic Types

type uint24le = record {
	byte3 : uint8;
	byte2 : uint8;
	byte1 : uint8;
};

type LengthEncodedInteger = record {
	length : uint8;
	integer : LengthEncodedIntegerLookahead(length);
};

type LengthEncodedIntegerLookahead(length: uint8) = record {
	val: case length of {
		0xfb    -> i0        : empty;
		0xfc    -> i2        : uint16;
		0xfd    -> i3        : uint24le;
		0xfe    -> i4        : uint64;
		0xff    -> err_packet: empty;
		default -> one       : empty;
	};
};

type LengthEncodedString = record {
	len: LengthEncodedInteger;
	val: bytestring &length=to_int()(len);
};

%header{
	class to_int
		{
		public:
		int operator()(uint24le* num) const
			{
			return (num->byte1() << 16) | (num->byte2() << 8) | num->byte3();
			}

		int operator()(LengthEncodedInteger* lei) const
			{
			if ( lei->length() < 0xfb )
				return lei->length();
			else if ( lei->length() == 0xfc )
				return lei->integer()->i2();
			else if ( lei->length() == 0xfd )
				return to_int()(lei->integer()->i3());
			else if ( lei->length() == 0xfe )
				return lei->integer()->i4();
			else
				return 0;
			}

		int operator()(LengthEncodedIntegerLookahead* lei) const
			{
			if ( lei->length() < 0xfb )
				return lei->length();
			else if ( lei->length() == 0xfc )
				return lei->i2();
			else if ( lei->length() == 0xfd )
				return to_int()(lei->i3());
			else if ( lei->length() == 0xfe )
				return lei->i4();
			else
				return 0;
			}
		};
%}

extern type to_int;

# Enums

enum command_consts {
	COM_SLEEP               = 0x00,
	COM_QUIT                = 0x01,
	COM_INIT_DB             = 0x02,
	COM_QUERY               = 0x03,
	COM_FIELD_LIST          = 0x04,
	COM_CREATE_DB           = 0x05,
	COM_DROP_DB             = 0x06,
	COM_REFRESH             = 0x07,
	COM_SHUTDOWN            = 0x08,
	COM_STATISTICS          = 0x09,
	COM_PROCESS_INFO        = 0x0a,
	COM_CONNECT             = 0x0b,
	COM_PROCESS_KILL        = 0x0c,
	COM_DEBUG               = 0x0d,
	COM_PING                = 0x0e,
	COM_TIME                = 0x0f,
	COM_DELAYED_INSERT      = 0x10,
	COM_CHANGE_USER         = 0x11,
	COM_BINLOG_DUMP         = 0x12,
	COM_TABLE_DUMP          = 0x13,
	COM_CONNECT_OUT         = 0x14,
	COM_REGISTER_SLAVE      = 0x15,
	COM_STMT_PREPARE        = 0x16,
	COM_STMT_EXECUTE        = 0x17,
	COM_STMT_SEND_LONG_DATA = 0x18,
	COM_STMT_CLOSE          = 0x19,
	COM_STMT_RESET          = 0x1a,
	COM_SET_OPTION          = 0x1b,
	COM_STMT_FETCH          = 0x1c,
	COM_DAEMON              = 0x1d,
	COM_BINLOG_DUMP_GTID    = 0x1e
};

enum state {
	CONNECTION_PHASE = 0,
	COMMAND_PHASE    = 1,
};

enum Expected {
	NO_EXPECTATION,
	EXPECT_STATUS,
	EXPECT_COLUMN_DEFINITION,
	EXPECT_COLUMN_COUNT,
	EXPECT_EOF1,
	EXPECT_EOF2,
	EXPECT_RESULTSET,
	EXPECT_QUERY_RESPONSE,
};

type NUL_String = RE/[^\0]*/;

# MySQL PDU

type MySQL_PDU(is_orig: bool) = record {
	hdr		: Header;
	msg		: case is_orig of {
		false -> server_msg: Server_Message(hdr.seq_id);
		true  -> client_msg: Client_Message(state);
	} &requires(state);
} &let {
	state	: int = $context.connection.get_state();
} &length=hdr.len &byteorder=bigendian;

type Header = record {
	le_len: uint24le;
	seq_id: uint8;
} &let {
	len   : uint32 = to_int()(le_len) + 4;
} &length=4;

type Server_Message(seq_id: uint8) = case seq_id of {
	0       -> initial_handshake: Initial_Handshake_Packet;
	default -> command_response : Command_Response;
};

type Client_Message(state: int) = case state of {
	CONNECTION_PHASE -> connection_phase: Handshake_Response_Packet;
	COMMAND_PHASE    -> command_phase   : Command_Request_Packet;
};

# Handshake Request

type Initial_Handshake_Packet = record {
	version		: uint8;
	pkt		: case version of {
		10      -> handshake10 : Handshake_v10;
		9       -> handshake9  : Handshake_v9;
		default -> error       : ERR_Packet;
	};
} &let {
	set_version		: bool = $context.connection.set_version(version);
};

type Handshake_v10 = record {
	server_version          : NUL_String;
	connection_id           : uint32;
	auth_plugin_data_part_1 : bytestring &length=8;
	filler_1                : uint8;
	capability_flag_1       : uint16;
	character_set           : uint8;
	status_flags            : uint16;
	capability_flags_2      : uint16;
	auth_plugin_data_len    : uint8;
	auth_plugin_name        : NUL_String;
};

type Handshake_v9 = record {
	server_version		: NUL_String;
	connection_id		: uint32;
	scramble			: NUL_String;
};

# Handshake Response

type Handshake_Response_Packet = case $context.connection.get_version() of {
	10	-> v10_response	: Handshake_Response_Packet_v10;
	9	-> v9_response	: Handshake_Response_Packet_v9;
} &let {
	version 			: uint8 = $context.connection.get_version();
} &byteorder=bigendian;

type Handshake_Response_Packet_v10 = record {
	cap_flags    : uint32;
	max_pkt_size : uint32;
	char_set     : uint8;
	pad          : padding[23];
	username     : NUL_String;
	password     : bytestring &restofdata;
};

type Handshake_Response_Packet_v9 = record {
	cap_flags		: uint16;
	max_pkt_size 	: uint24le;
	username     	: NUL_String;
	auth_response	: NUL_String;
	have_db			: case ( cap_flags & 0x8 ) of {
		0x8	-> database : NUL_String;
		0x0	-> none	    : empty;
	};
	password     	: bytestring &restofdata;
};

# Command Request

type Command_Request_Packet = record {
	command			: uint8;
	arg    			: bytestring &restofdata;
} &let {
	update_expectation	: bool = $context.connection.set_next_expected(EXPECT_COLUMN_COUNT);
};

# Command Response

type Command_Response = case $context.connection.get_expectation() of {
	EXPECT_COLUMN_COUNT		-> col_count_meta	: ColumnCountMeta;
	EXPECT_COLUMN_DEFINITION	-> col_defs		: ColumnDefinitions;
	EXPECT_RESULTSET		-> resultset		: Resultset;
	EXPECT_STATUS			-> status		: Command_Response_Status;
	EXPECT_EOF1			-> eof1			: EOF1;
	EXPECT_EOF2			-> eof2			: EOF2;
	default				-> unknow		: empty;
};

type Command_Response_Status = record {
	pkt_type: uint8;
	response: case pkt_type of {
		0x00    -> data_ok:   OK_Packet;
		0xfe    -> data_eof:  EOF_Packet;
		0xff    -> data_err:  ERR_Packet;
		default -> unknown:   empty;
	};
};

type ColumnCountMeta = record {
	byte	: uint8;
	pkt_type: case byte of {
		0x00    -> ok		: OK_Packet;
		0xff    -> err		: ERR_Packet;
#		0xfb    -> Not implemented
		default -> col_count: ColumnCount(byte);
	};
};

type ColumnCount(byte: uint8) = record {
	le_column_count		: LengthEncodedIntegerLookahead(byte);
} &let {
	col_num			: uint32 = to_int()(le_column_count);
	update_col_num		: bool = $context.connection.set_col_count(col_num);
	update_expectation	: bool = $context.connection.set_next_expected(EXPECT_COLUMN_DEFINITION);
};

type ColumnDefinitions = record {
	defs				: ColumnDefinition41[1];
} &let {
	update_expectation	: bool = $context.connection.set_next_expected(EXPECT_EOF1);
};

type EOF1 = record {
	eof					: EOF_Packet;
} &let {
	update_expectation	: bool = $context.connection.set_next_expected(EXPECT_RESULTSET);
};

type EOF2 = record {
	eof					: EOF_Packet;
} &let {
	update_expectation	: bool = $context.connection.set_next_expected(NO_EXPECTATION);
};

type Resultset = record {
	rows				: ResultsetRow[] &until($input.length()==0);
} &let {
	update_expectation	: bool = $context.connection.set_next_expected(EXPECT_EOF2);
};

type ResultsetRow = record {
	fields: LengthEncodedString[$context.connection.get_col_count()];
};

type ColumnDefinition41 = record {
	catalog  : LengthEncodedString;
	schema   : LengthEncodedString;
	table    : LengthEncodedString;
	org_table: LengthEncodedString;
	name     : LengthEncodedString;
	org_name : LengthEncodedString;
	next_len : LengthEncodedInteger;
	char_set : uint16;
	col_len  : uint32;
	type     : uint8;
	flags    : uint16;
	decimals : uint8;
	filler   : padding[2];
};

type ColumnDefinition320 = record {
	table            : LengthEncodedString;
	name             : LengthEncodedString;
	length_of_col_len: LengthEncodedInteger;
	col_len          : uint24le;
	type_len         : LengthEncodedInteger;
	type             : uint8;
};

type OK_Packet = record {
	le_rows		: LengthEncodedInteger;
	todo   		: bytestring &restofdata;
} &let {
	rows        : uint32 = to_int()(le_rows);
	update_state: bool   = $context.connection.update_state(COMMAND_PHASE);
};

type ERR_Packet = record {
	code : uint16;
	state: bytestring &length=6;
	msg  : bytestring &restofdata;
} &let {
	update_state: bool = $context.connection.update_state(COMMAND_PHASE);
};

type EOF_Packet = record {
	warnings: uint16;
	status  : uint16;
} &let {
	update_state: bool = $context.connection.update_state(COMMAND_PHASE);
};

# State tracking

refine connection MySQL_Conn += {
	%member{
		uint8 version_;
		int state_;
		Expected expected_;
		uint32 col_count_;
	%}

	%init{
		version_ = 0;
		state_ = CONNECTION_PHASE;
		expected_ = EXPECT_STATUS;
		col_count_ = 0;
	%}

	function get_version(): uint8
		%{
		return version_;
		%}

	function set_version(v: uint8): bool
		%{
		version_ = v;
		return true;
		%}

	function get_state(): int
		%{
		return state_;
		%}

	function update_state(s: state): bool
		%{
		state_ = s;
		return true;
		%}

	function get_expectation(): Expected
		%{
		return expected_;
		%}

	function set_next_expected(e: Expected): bool
		%{
		expected_ = e;
		return true;
		%}

	function get_col_count(): uint32
		%{
		return col_count_;
		%}

	function set_col_count(i: uint32): bool
		%{
		col_count_ = i;
		return true;
		%}
};
