###
#
# All information is from the MySQL internals documentation at:
# <http://dev.mysql.com/doc/internals/en/connection-phase.html>
#
###

type uint24le = record {
	byte3 : uint8;
	byte2 : uint8;
	byte1 : uint8;
};

type LengthEncodedInteger = record {
	i1: uint8;
	val: case i1 of {
		0xfb    -> i0: empty;
		0xfc    -> i2: uint16;
		0xfd    -> i3: uint24le;
		0xfe    -> i4: uint64;
		0xff    -> err_packet: empty;
		default -> one: empty;
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
		int operator()(uint24le * num) const
			{
			return (num->byte1() << 16) | (num->byte2() << 8) | num->byte3();
			}
		int operator()(LengthEncodedInteger* lei) const
			{
			if ( lei->i1() < 0xfb )
				return lei->i1();
			else if ( lei->i1() == 0xfc )
				return lei->i2();
			else if ( lei->i1() == 0xfd )
				return to_int()(lei->i3());
			else if ( lei->i1() == 0xfe )
				return lei->i4();
			else 
				return 0;
			}

		};
%}

extern type to_int;

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
	EXPECT_RESULTSET,
	EXPECT_RESULTSETROW,
};

type NUL_String = RE/[^\0]*/;

type MySQL_PDU(is_orig: bool) = record {
	len: uint24le;
	pkt: MySQL_Packet(this);
} &let {
	real_len: uint32 = to_int()(len);
} &byteorder=bigendian &length=4+real_len;

type MySQL_Packet(pdu: MySQL_PDU) = record {
	seq_id: uint8;
	msg:    case pdu.is_orig of {
		false -> server_msg: Server_Message(this);
		true  -> client_msg: Client_Message;
	};

	# In case there is trash left over from not parsing something completely.
	blah: bytestring &restofdata;
} &byteorder=bigendian;

type Client_Message = case $context.connection.get_state() of {
	CONNECTION_PHASE -> connection_phase: Handshake_Response_Packet;
	COMMAND_PHASE    -> command_phase:    Command_Request_Packet;
};

type Server_Message(p: MySQL_Packet) = case p.seq_id of {
	0       -> initial_handshake: Initial_Handshake_Packet;
	default -> command_response:  Command_Response;
};

type Initial_Handshake_Packet = record {
	protocol_version: uint8;
	pkt: case protocol_version of {
		10      -> handshake10 : Handshake_v10;
		9       -> handshake9  : Handshake_v9;
		default -> error       : ERR_Packet;
	};
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
	todo: bytestring &restofdata;
};

type Handshake_Response_Packet = record {
	cap_flags    : uint32;
	max_pkt_size : uint32;
	char_set     : uint8;
	pad          : padding[23];
	username     : NUL_String;
	password     : bytestring &restofdata;
} &byteorder=bigendian;

type Command_Request_Packet = record {
	command: uint8;
	arg:     bytestring &restofdata;
};

type Command_Response = case $context.connection.get_expectation() of {
	EXPECT_COLUMN_DEF   -> col_def      : ColumnDefinition41;
	EXPECT_RESULTSET    -> resultset    : Resultset;
	EXPECT_RESULTSETROW -> resultsetrow : ResultsetRow;
	EXPECT_STATUS       -> status       : Command_Response_Status;
	default             -> unknown      : empty;
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

type Resultset = record {
	column_count: LengthEncodedInteger;
	#columns:      ColumnDefinition41[col_num];
	#eof:          EOF_Packet;
	#rows:         ResultsetRow(col_num)[] &until($input.length()==0);
	#eof2          EOF_Packet;
} &let {
	col_num: uint32 = to_int()(column_count);
	set_count = $context.connection.set_col_count(col_num);
};

type ResultsetRow = record {
	fields: LengthEncodedString[$context.connection.get_col_count];
};

type ColumnDefinition41 = record {
	catalog:   LengthEncodedString;
	schema:    LengthEncodedString;
	table:     LengthEncodedString;
	org_table: LengthEncodedString;
	name:      LengthEncodedString;
	org_name:  LengthEncodedString;
	next_len:  LengthEncodedInteger;
	char_set:  uint16;
	col_len:   uint32;
	type:      uint8;
	flags:     uint16;
	decimals:  uint8;
	filler:    padding[2];
	#if command was COM_FIELD_LIST {
	#  lenenc_int     length of default-values
	#  string[$len]   default values
	#}
};

type ColumnDefinition320 = record {
	table:   LengthEncodedString;
	name:    LengthEncodedString;
	length_of_col_len: LengthEncodedInteger;
	col_len: uint24le;
	type_len: LengthEncodedInteger;
	type:     uint8;
	#if capabilities & CLIENT_LONG_FLAG {
	#lenenc_int     [03] length of flags+decimals fields
	#2              flags
	#1              decimals
	#  } else {
	#1              [02] length of flags+decimals fields
	#1              flags
	#1              decimals
	#  }
	#  if command was COM_FIELD_LIST {
	#lenenc_int     length of default-values
	#string[$len]   default values
	#  }
};

type OK_Packet = record {
	todo: bytestring &restofdata;
} &let {
	update_state: bool = $context.connection.update_state(COMMAND_PHASE);
};

type ERR_Packet = record {
	todo: bytestring &restofdata;
};

type EOF_Packet = record {
	todo: bytestring &restofdata;
};


refine connection MySQL_Conn += {
	%member{
		int state_;
		Expected expected_;
		uint32 col_count_;
	%}

	%init{
		state_ = CONNECTION_PHASE;
		expected_ = NO_EXPECTATION;
		col_count_ = 0;
	%}

	function get_state(): int
		%{ 
		return state_; 
		%}

	function update_state(s: state): bool
		%{
		printf("updating state\n");
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
