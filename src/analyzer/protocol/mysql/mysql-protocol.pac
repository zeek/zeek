# See the file "COPYING" in the main distribution directory for copyright.
#
# All information is from the MySQL internals documentation at:
# <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>
#

# Basic Types

type uint24le = record {
	byte3: uint8;
	byte2: uint8;
	byte1: uint8;
};

type LengthEncodedInteger = record {
	length : uint8;
	integer: LengthEncodedIntegerLookahead(length);
};

type LengthEncodedIntegerArg(length: uint8) = record {
	integer: LengthEncodedIntegerLookahead(length);
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

type LengthEncodedStringArg(first_byte: uint8) = record {
	len: LengthEncodedIntegerArg(first_byte);
	val: bytestring &length=to_int()(len);
};

%header{
	class to_int
		{
		public:
		int operator()(uint24le* num) const
			{
			// Convert 24bit little endian int parsed as 3 uint8 into host endianness.
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

		int operator()(LengthEncodedIntegerArg* lei) const
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
	COM_BINLOG_DUMP_GTID    = 0x1e,
	COM_RESET_CONNECTION    = 0x1f,
};

enum state {
	CONNECTION_PHASE = 0,
	COMMAND_PHASE    = 1,
};

enum ConnectionExpected {
	EXPECT_HANDSHAKE,
	EXPECT_AUTH_DATA,
};

enum Expected {
	NO_EXPECTATION,
	EXPECT_STATUS,
	EXPECT_COLUMN_DEFINITION,
	EXPECT_COLUMN_DEFINITION_OR_EOF,
	EXPECT_COLUMN_COUNT,
	EXPECT_EOF_THEN_RESULTSET,
	EXPECT_RESULTSET,
	EXPECT_REST_OF_PACKET,
};

enum EOFType {
	EOF_INTERMEDIATE,  # column definition to result row transition
	EOF_END,
};

enum Client_Capabilities {
	CLIENT_CONNECT_WITH_DB = 0x00000008,
	CLIENT_SSL           = 0x00000800,
	CLIENT_PLUGIN_AUTH   = 0x00080000,
	CLIENT_CONNECT_ATTRS = 0x00100000,
	# Expects an OK (instead of EOF) after the resultset rows of a Text Resultset.
	CLIENT_DEPRECATE_EOF = 0x01000000,
	CLIENT_ZSTD_COMPRESSION_ALGORITHM = 0x04000000,
	CLIENT_QUERY_ATTRIBUTES = 0x08000000,
};

# Binary Protocol Resultset encoding.
#
# https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_binary_resultset.html
#
# Values taken from here: https://dev.mysql.com/doc/dev/mysql-server/latest/namespaceclassic__protocol_1_1field__type.html
enum field_types {
	TYPE_DECIMAL = 0x00,
	TYPE_TINY = 0x01,
	TYPE_SHORT = 0x02,
	TYPE_LONG = 0x03,
	TYPE_FLOAT = 0x04,
	TYPE_DOUBLE = 0x05,
	TYPE_NULL = 0x06,
	TYPE_TIMESTAMP = 0x07,
	TYPE_LONGLONG = 0x08,
	TYPE_INT24 = 0x09,
	TYPE_DATE = 0x0a,
	TYPE_TIME = 0x0b,
	TYPE_DATETIME = 0x0c,
	TYPE_YEAR = 0x0d,
	TYPE_VARCHAR = 0x0f,
	TYPE_BIT = 0x10,
	TYPE_TIMESTAMP2 = 0x11,
	TYPE_JSON = 0xf5,
	TYPE_NEWDECIMAL = 0xf6,
	TYPE_ENUM = 0xf7,
	TYPE_SET = 0xf8,
	TYPE_TINYBLOB = 0xf9,
	TYPE_MEDIUMBLOB = 0xfa,
	TYPE_LONGBLOB = 0xfb,
	TYPE_BLOB = 0xfc,
	TYPE_VARSTRING = 0xfd,
	TYPE_STRING = 0xfe,
	TYPE_GEOMETRY = 0xff,
};

type Date = record {
	year : int16;
	month: int8;
	day  : int8;
};

type Time = record {
	hour  : int8;
	minute: int8;
	second: int8;
};

type BinaryDate = record {
	len: uint8 &enforce(len == 0 || len == 4 || len == 7 || len == 11);
	have_date: case ( len > 0 ) of {
		true  -> date  : Date;
		false -> none_1: empty;
	};
	have_time: case ( len > 4 ) of {
		true  -> time  : Time;
		false -> none_2: empty;
	};
	have_micros: case ( len > 7 ) of {
		true  -> micros: int32;
		false -> none_3: empty;
	};
};

type DurationTime = record {
	is_negative: int8 &enforce(is_negative == 0 || is_negative == 1);
	days       : int32;
	time       : Time;
};

type BinaryTime = record {
	len: uint8 &enforce(len == 0 || len == 8 || len == 12);
	have_time: case ( len > 0 ) of {
		true  -> time  : DurationTime;
		false -> none_1: empty;
	};
	have_micros: case ( len > 8 ) of {
		true  -> micros: int32;
		false -> none_2: empty;
	};
};

type BinaryValue(type: uint16) = record {
	value:  case ( type ) of {
		TYPE_DECIMAL -> decimal_val: LengthEncodedInteger;
		TYPE_TINY -> tiny_val: int8;
		TYPE_SHORT -> short_val: int16;
		TYPE_LONG -> long_val: int32;
		TYPE_FLOAT -> float_val: bytestring &length=4;
		TYPE_DOUBLE -> double_val: bytestring &length=8;
		TYPE_NULL -> null_val: empty;  # in null_bitmap
		TYPE_TIMESTAMP -> timestamp_val: BinaryDate;
		TYPE_LONGLONG -> longlong_val: int64;
		TYPE_INT24 -> int24_val: int32;
		TYPE_DATE -> date_val: BinaryDate;
		TYPE_TIME -> time_val: BinaryTime;
		TYPE_DATETIME -> datetime_val: BinaryDate;
		TYPE_YEAR -> year_val: int16;
		TYPE_VARCHAR -> varchar_val: LengthEncodedString;
		TYPE_BIT -> bit_val: LengthEncodedString;
		TYPE_TIMESTAMP2 -> timestamp2_val: BinaryDate;
		TYPE_JSON -> json_val: LengthEncodedString;
		TYPE_NEWDECIMAL -> newdecimal_val: LengthEncodedString;
		TYPE_ENUM -> enum_val: LengthEncodedString;
		TYPE_SET -> set_val: LengthEncodedString;
		TYPE_TINYBLOB -> tinyblob_val: LengthEncodedString;
		TYPE_MEDIUMBLOB -> mediumblob_val: LengthEncodedString;
		TYPE_LONGBLOB -> longblob_val: LengthEncodedString;
		TYPE_BLOB -> blob_val: LengthEncodedString;
		TYPE_VARSTRING -> varstring_val: LengthEncodedString;
		TYPE_STRING -> string_val: LengthEncodedString;
		TYPE_GEOMETRY -> geometry_val: LengthEncodedString;
	};
};

type NUL_String = RE/[^\0]*\0/;
type EmptyOrNUL_String = RE/([^\0]*\0)?/;

# MySQL PDU

type MySQL_PDU(is_orig: bool) = record {
	hdr  : Header;
	msg  : case is_orig of {
		false -> server_msg: Server_Message(hdr.seq_id, hdr.len, state);
		true  -> client_msg: Client_Message(hdr.len, state);
	} &requires(state);
} &let {
	state: int = $context.connection.get_state();
} &length=hdr.len &byteorder=littleendian;

type Header = record {
	le_len: uint24le;
	seq_id: uint8;
} &let {
	len   : uint32 = to_int()(le_len) + 4;
} &length=4;

type Server_Message(seq_id: uint8, pkt_len: uint32, state: int) = case state of {
	CONNECTION_PHASE -> connection_phase: Server_Connection_Phase(is_initial);
	COMMAND_PHASE    -> command_response: Command_Response(pkt_len);
} &requires(is_initial) &let {
	is_initial : bool = (seq_id == 0) && ($context.connection.get_previous_seq_id() != 255);
	update_seq_id : bool = $context.connection.set_previous_seq_id(seq_id);
};

type Server_Connection_Phase(is_initial: bool) = case is_initial of {
	true  -> initial_handshake: Initial_Handshake_Packet;
	false -> subsequent_handshake: Server_Connection_Phase_Packets;
};

# Handshake Request

type Initial_Handshake_Packet = record {
	version    : uint8;
	pkt        : case version of {
		10      -> handshake10: Handshake_v10;
		9       -> handshake9 : Handshake_v9;
		default -> error      : ERR_Packet;
	};
} &let {
	set_version: bool = $context.connection.set_version(version);
};

type Handshake_v10 = record {
	server_version         : NUL_String;
	connection_id          : uint32;
	auth_plugin_data_part_1: bytestring &length=8;
	filler_1               : uint8;
	capability_flag_1      : uint16;
	character_set          : uint8;
	status_flags           : uint16;
	capability_flags_2     : uint16;
	auth_plugin_data_len   : uint8 &enforce( auth_plugin_data_len==0 || auth_plugin_data_len >= 21);
	reserved               : padding[10];
	auth_plugin_data_part_2: bytestring &length=auth_plugin_data_part_2_len;
	have_plugin : case ( ( capability_flags_2 << 16 ) & CLIENT_PLUGIN_AUTH ) of {
		CLIENT_PLUGIN_AUTH -> auth_plugin: NUL_String;
		0x0 -> none    : empty;
	};
} &let {
	# The length of auth_plugin_data_part_2 is at least 13 bytes,
	# or auth_plugin_data_len - 8 if that is larger, check for
	# auth_plugin_data_len > 21 (8 + 13) to prevent underflow for
	# when subtracting 8.
	#
	# https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html
	auth_plugin_data_part_2_len = auth_plugin_data_len > 21 ? auth_plugin_data_len - 8 : 13;
	server_query_attrs: bool = $context.connection.set_server_query_attrs(( capability_flags_2 << 16 ) & CLIENT_QUERY_ATTRIBUTES);
};

type Handshake_v9 = record {
	server_version: NUL_String;
	connection_id : uint32;
	scramble      : NUL_String;
};

# While in the CONNECTION_PHASE, handle the following packets. Note that
# this is subtly different from Command_Response_Status which interprets
# 0xfe as EOF packet and also has does not support AuthMoreData.
type Server_Connection_Phase_Packets = record {
	pkt_type: uint8;
	packet: case pkt_type of {
		0x00 -> data_ok: OK_Packet;
		0x01 -> auth_more_data: AuthMoreData(false);
		0xfe -> auth_switch_request: AuthSwitchRequest;
		0xff -> data_err: ERR_Packet;
	};
};

# Handshake Response

type Handshake_Response_Packet = case $context.connection.get_version() of {
	10 -> v10_response: Handshake_Response_Packet_v10;
	9  -> v9_response : Handshake_Response_Packet_v9;
} &let {
	version: uint8 = $context.connection.get_version();
};

type Handshake_Credentials_v10 = record {
	username : NUL_String;
	password : LengthEncodedString;
};

type Connection_Attribute = record {
	name  : LengthEncodedString;
	value : LengthEncodedString;
};

type Handshake_Connection_Attributes = record {
	length : uint8;
	attrs  : Connection_Attribute[] &until($input.length() == 0);
} &length = length+1;

type Handshake_Plain_v10(cap_flags: uint32) = record {
	credentials: Handshake_Credentials_v10;
	have_db     : case ( cap_flags & CLIENT_CONNECT_WITH_DB ) of {
		CLIENT_CONNECT_WITH_DB -> database: NUL_String;
		0x0 -> none_1    : empty;
	};
	have_plugin : case ( cap_flags & CLIENT_PLUGIN_AUTH ) of {
		CLIENT_PLUGIN_AUTH -> auth_plugin: EmptyOrNUL_String;
		0x0 -> none_2    : empty;
	};
	have_attrs  : case ( cap_flags & CLIENT_CONNECT_ATTRS ) of {
		CLIENT_CONNECT_ATTRS -> conn_attrs: Handshake_Connection_Attributes;
		0x0 -> none_3    : empty;
	};
	have_zstd   : case ( cap_flags & CLIENT_ZSTD_COMPRESSION_ALGORITHM ) of {
		CLIENT_ZSTD_COMPRESSION_ALGORITHM -> zstd_compression_level: uint8;
		0x0 -> none_4    : empty;
	};
} &let {
	# Switch client state into expecting more auth data. If the server responds
	# with an OK_Packet before, will switch into COMMAND_PHASE.
	update_conn_expectation: bool = $context.connection.set_next_conn_expected(EXPECT_AUTH_DATA)
		&if( cap_flags & CLIENT_PLUGIN_AUTH );
};

type Handshake_Response_Packet_v10 = record {
	cap_flags   : uint32;
	max_pkt_size: uint32;
	char_set    : uint8;
	pad         : padding[23];
	use_ssl     : case ( cap_flags & CLIENT_SSL ) of {
		CLIENT_SSL -> none    : empty;
		default -> plain: Handshake_Plain_v10(cap_flags);
	};
} &let {
	deprecate_eof: bool = $context.connection.set_deprecate_eof(cap_flags & CLIENT_DEPRECATE_EOF);
	client_query_attrs: bool = $context.connection.set_client_query_attrs(cap_flags & CLIENT_QUERY_ATTRIBUTES);
	proc_cap_flags: bool = $context.connection.set_client_capabilities(cap_flags);
};

type Handshake_Response_Packet_v9 = record {
	cap_flags    : uint16;
	max_pkt_size : uint24le;
	username     : NUL_String;
	auth_response: NUL_String;
	have_db      : case ( cap_flags & CLIENT_CONNECT_WITH_DB ) of {
		CLIENT_CONNECT_WITH_DB -> database: NUL_String;
		0x0 -> none    : empty;
	};
	password     : bytestring &restofdata;
};

# Connection Phase

type Client_Message(pkt_len: uint32, state: int) = case state of {
	CONNECTION_PHASE -> connection_phase: Connection_Phase_Packets;
	COMMAND_PHASE    -> command_phase   : Command_Request_Packet(pkt_len);
};

type Connection_Phase_Packets = case $context.connection.get_conn_expectation() of {
	EXPECT_HANDSHAKE        -> handshake_resp: Handshake_Response_Packet;
	EXPECT_AUTH_DATA        -> auth_data: AuthMoreData(true);
};

# Query attribute handling for COM_QUERY
#
type AttributeTypeAndName = record {
	type: uint8;
	unsigned_flag: uint8;
	name: LengthEncodedString;
};

type AttributeValue(is_null: bool, type: uint8) = record {
	null: case is_null of {
		false -> val: BinaryValue(type);
		true -> null_val: empty;
	};
} &let {
	# Move parsing the next query attribute.
	done = $context.connection.next_query_attr();
};

type Attributes(count: int) = record {
	null_bitmap         : bytestring &length=(count + 7) / 8;
	send_types_to_server: uint8 &enforce(send_types_to_server == 1);
	names               : AttributeTypeAndName[count];
	values              : AttributeValue(
		# Check if null_bitmap contains this attribute index. This
		# will pass true if the attribute value is NULL and parsing
		# skipped in AttributeValue above.
		(null_bitmap[$context.connection.query_attr_idx() / 8] >> ($context.connection.query_attr_idx() % 8)) & 0x01,
		names[$context.connection.query_attr_idx()].type
	)[] &until($context.connection.query_attr_idx() >= count);
};

type Query_Attributes = record {
	count    : LengthEncodedInteger;
	set_count: LengthEncodedInteger;
	have_attr: case ( attr_count > 0 ) of {
		true  -> attrs: Attributes(attr_count);
		false -> none: empty;
	} &requires(new_query_attrs);
} &let {
	attr_count: int = to_int()(count);
	new_query_attrs = $context.connection.new_query_attrs();
};

# Command Request

type Command_Request_Packet(pkt_len: uint32) = record {
	command: uint8;
	attrs  : case ( command == COM_QUERY && $context.connection.get_client_query_attrs() && $context.connection.get_server_query_attrs() ) of {
		true  -> query_attrs: Query_Attributes;
		false -> none: empty;
	};

	have_change_user: case is_change_user of {
		true  -> change_user: Change_User_Packet(pkt_len);
		false -> none_change_user: empty;
	};

	arg    : bytestring &restofdata;
} &let {
	is_change_user = command == COM_CHANGE_USER;
	update_expectation: bool = $context.connection.set_next_expected_from_command(command);
};

# Command from the client to switch the user mid-session.
#
# https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_change_user.html
type Change_User_Packet(pkt_len: uint32) = record {
	username : NUL_String;
	auth_plugin_data_len: uint8;
	auth_plugin_data: bytestring &length=auth_plugin_data_len;
	database: NUL_String;
	charset: uint16;

	auth_plugin_name_case: case have_auth_plugin_name of {
		true -> auth_plugin_name: NUL_String;
		false -> no_more_data1: empty;
	};

	conn_attrs_case: case have_conn_attrs of {
		true -> conn_attrs: Handshake_Connection_Attributes;
		false -> no_conn_attrs: empty;
	};
} &let {
	have_more_data = offsetof(auth_plugin_name_case) < pkt_len;
	have_auth_plugin_name = have_more_data && ($context.connection.get_client_capabilities() & CLIENT_PLUGIN_AUTH) == CLIENT_PLUGIN_AUTH;
	have_conn_attrs = have_more_data && ($context.connection.get_client_capabilities() & CLIENT_CONNECT_ATTRS) == CLIENT_CONNECT_ATTRS;
} &exportsourcedata;

# Command Response

type Command_Response(pkt_len: uint32) = case $context.connection.get_expectation() of {
	EXPECT_COLUMN_COUNT             -> col_count_meta: ColumnCountMeta;
	EXPECT_COLUMN_DEFINITION        -> col_def       : ColumnDefinition;
	EXPECT_COLUMN_DEFINITION_OR_EOF -> def_or_eof    : ColumnDefinitionOrEOF(pkt_len);
	EXPECT_RESULTSET                -> resultset     : Resultset(pkt_len);
	EXPECT_REST_OF_PACKET           -> rest          : bytestring &restofdata;
	EXPECT_STATUS                   -> status        : Command_Response_Status;
	EXPECT_EOF_THEN_RESULTSET       -> eof           : EOFIfLegacyThenResultset(pkt_len);
	default                         -> unknown       : empty;
};

type Command_Response_Status = record {
	pkt_type: uint8;
	response: case pkt_type of {
		0x00    -> data_ok:  OK_Packet;
		0xfe    -> data_eof: EOF_Packet(EOF_END);
		0xff    -> data_err: ERR_Packet;
		default -> unknown:  empty;
	};
};

type ColumnCountMeta = record {
	byte	: uint8;
	pkt_type: case byte of {
		0x00    -> ok       : OK_Packet;
		0xff    -> err      : ERR_Packet;
#		0xfb    -> Not implemented
		default -> col_count: ColumnCount(byte);
	};
};

type ColumnCount(byte: uint8) = record {
	le_column_count   : LengthEncodedIntegerLookahead(byte);
} &let {
	col_num           : uint32 = to_int()(le_column_count);
	update_col_num    : bool   = $context.connection.set_col_count(col_num);
	update_remain     : bool   = $context.connection.set_remaining_cols(col_num);
	update_expectation: bool   = $context.connection.set_next_expected(EXPECT_COLUMN_DEFINITION);
};

type ColumnDefinition = record {
	dummy: uint8;
	def  : ColumnDefinition41(dummy);
} &let {
	update_remain     : bool = $context.connection.dec_remaining_cols();
	update_expectation: bool = $context.connection.set_next_expected($context.connection.get_remaining_cols() > 0 ? EXPECT_COLUMN_DEFINITION : EXPECT_EOF_THEN_RESULTSET);
};

# Only used to indicate the end of a result, no intermediate eofs here.
# MySQL spec says "You must check whether the packet length is less than 9
# to make sure that it is a EOF_Packet packet" so the value of 13 here
# comes from that 9, plus a 4-byte header.
type EOFOrOK(pkt_len: uint32) = case ( $context.connection.get_deprecate_eof() || pkt_len > 13 ) of {
	false -> eof: EOF_Packet(EOF_END);
	true  -> ok: OK_Packet;
};

type ColumnDefinitionOrEOF(pkt_len: uint32) = record {
	marker    : uint8;
	def_or_eof: case is_eof_or_ok of {
		true  -> eof: EOFOrOK(pkt_len);
		false -> def: ColumnDefinition41(marker);
	} &requires(is_eof_or_ok);
} &let {
	is_eof_or_ok: bool = (marker == 0xfe);
};


type EOFIfLegacyThenResultset(pkt_len: uint32) = case $context.connection.get_deprecate_eof() of {
	false -> eof: EOF_Packet_With_Marker(EOF_INTERMEDIATE);
	true  -> resultset: Resultset(pkt_len);
} &let {
	update_result_seen: bool = $context.connection.set_results_seen(0);
	update_expectation: bool = $context.connection.set_next_expected(EXPECT_RESULTSET) &if( ! $context.connection.get_deprecate_eof() );
};

type Resultset(pkt_len: uint32) = record {
	marker    : uint8;
	row_or_eof: case is_eof_or_ok of {
		true  -> eof: EOFOrOK(pkt_len);
		false -> row: ResultsetRow(marker);
	} &requires(is_eof_or_ok);
} &let {
	is_eof_or_ok      : bool = (marker == 0xfe);
	update_result_seen: bool = $context.connection.inc_results_seen();
	update_expectation: bool = $context.connection.set_next_expected(is_eof_or_ok ? NO_EXPECTATION : EXPECT_RESULTSET);
};

type ResultsetRow(first_byte: uint8) = record {
	first_field: LengthEncodedStringArg(first_byte);
	fields     : LengthEncodedString[$context.connection.get_col_count() - 1];
};

type ColumnDefinition41(first_byte: uint8) = record {
	catalog  : LengthEncodedStringArg(first_byte);
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

# Opaque auth data exchanged during the connection phase between client and server.
type AuthMoreData(is_orig: bool) = record {
	data  : bytestring &restofdata;
};

type AuthSwitchRequest = record {
	name  : NUL_String;
	data  : bytestring &restofdata;
} &let {
	update_conn_expectation: bool = $context.connection.set_next_conn_expected(EXPECT_AUTH_DATA);
	# After an AuthSwitchRequest, server replies with OK_Packet, ERR_Packet or AuthMoreData.
	update_expectation: bool = $context.connection.set_next_expected(EXPECT_STATUS);
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
	le_rows: LengthEncodedInteger;
	todo   : bytestring &restofdata;
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

type EOF_Packet(typ: EOFType) = record {
	warnings: uint16;
	status  : uint16;
};

type EOF_Packet_With_Marker(typ: EOFType) = record {
	marker : uint8;
	payload: EOF_Packet(typ);
} &let {
	update_state: bool = $context.connection.update_state(COMMAND_PHASE);
};

# State tracking

refine connection MySQL_Conn += {
	%member{
		uint8 version_;
		uint8 previous_seq_id_;
		int state_;
		Expected expected_;
		ConnectionExpected conn_expected_;
		uint32 col_count_;
		uint32 remaining_cols_;
		uint32 results_seen_;
		bool deprecate_eof_;
		bool server_query_attrs_;
		bool client_query_attrs_;
		uint32 client_capabilities_;
		std::string auth_plugin_;
		int query_attr_idx_;
	%}

	%init{
		version_ = 0;
		previous_seq_id_ = 0;
		state_ = CONNECTION_PHASE;
		expected_ = EXPECT_STATUS;
		conn_expected_ = EXPECT_HANDSHAKE;
		col_count_ = 0;
		remaining_cols_ = 0;
		results_seen_ = 0;
		deprecate_eof_ = false;
		server_query_attrs_ = false;
		client_query_attrs_ = false;
		query_attr_idx_ = 0;
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

	function get_previous_seq_id(): uint8
		%{
		return previous_seq_id_;
		%}

	function set_previous_seq_id(s: uint8): bool
		%{
		previous_seq_id_ = s;
		return true;
		%}

	function get_state(): int
		%{
		return state_;
		%}

	function update_state(s: state): bool
		%{
		state_ = s;

		if ( s == COMMAND_PHASE )
			conn_expected_ = EXPECT_HANDSHAKE; // Reset connection phase expectation

		return true;
		%}

	function get_deprecate_eof(): bool
		%{
		return deprecate_eof_;
		%}

	function set_deprecate_eof(d: bool): bool
		%{
		deprecate_eof_ = d;
		return true;
		%}

	function get_server_query_attrs(): bool
		%{
		return server_query_attrs_;
		%}

	function set_server_query_attrs(q: bool): bool
		%{
		server_query_attrs_ = q;
		return true;
		%}

	function get_client_query_attrs(): bool
		%{
		return client_query_attrs_;
		%}

	function set_client_query_attrs(q: bool): bool
		%{
		client_query_attrs_ = q;
		return true;
		%}

	function set_client_capabilities(c: uint32): bool
		%{
		client_capabilities_ = c;
		return true;
		%}

	function get_client_capabilities(): uint32
		%{
		return client_capabilities_;
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

	function get_conn_expectation(): ConnectionExpected
		%{
		return conn_expected_;
		%}

	function set_next_conn_expected(c: ConnectionExpected): bool
		%{
		conn_expected_ = c;
		return true;
		%}

	function set_next_expected_from_command(cmd: uint8): bool
		%{
		switch ( cmd ) {
		case COM_SLEEP:
		case COM_QUIT:
		case COM_INIT_DB:
		case COM_CREATE_DB:
		case COM_DROP_DB:
		case COM_REFRESH:
		case COM_SHUTDOWN:
		case COM_CONNECT:
		case COM_PROCESS_KILL:
		case COM_DEBUG:
		case COM_PING:
		case COM_TIME:
		case COM_DELAYED_INSERT:
		case COM_DAEMON:
		case COM_RESET_CONNECTION:
			expected_ = EXPECT_STATUS;
			break;
		case COM_QUERY:
		case COM_PROCESS_INFO:
			expected_ = EXPECT_COLUMN_COUNT;
			break;
		case COM_FIELD_LIST:
			expected_ = EXPECT_COLUMN_DEFINITION_OR_EOF;
			break;
		case COM_STATISTICS:
			expected_ = EXPECT_REST_OF_PACKET;
			break;
		case COM_CHANGE_USER:
			update_state(CONNECTION_PHASE);
			break;
		case COM_BINLOG_DUMP:
		case COM_TABLE_DUMP:
		case COM_CONNECT_OUT:
		case COM_REGISTER_SLAVE:
		case COM_STMT_PREPARE:
		case COM_STMT_EXECUTE:
		case COM_STMT_SEND_LONG_DATA:
		case COM_STMT_CLOSE:
		case COM_STMT_RESET:
		case COM_SET_OPTION:
		case COM_STMT_FETCH:
		case COM_BINLOG_DUMP_GTID:
		default:
			expected_ = NO_EXPECTATION;
			break;
		}
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

	function get_remaining_cols(): uint32
		%{
		return remaining_cols_;
		%}

	function set_remaining_cols(i: uint32): bool
		%{
		remaining_cols_ = i;
		return true;
		%}

	function dec_remaining_cols(): bool
		%{
		--remaining_cols_;
		return true;
		%}

	function get_results_seen(): uint32
		%{
		return results_seen_;
		%}

	function set_results_seen(i: uint32): bool
		%{
		results_seen_ = i;
		return true;
		%}

	function inc_results_seen(): bool
		%{
		++results_seen_;
		return true;
		%}

	function query_attr_idx(): int
		%{
		return query_attr_idx_;
		%}

	function new_query_attrs(): bool
		%{
		query_attr_idx_ = 0;
		return true;
		%}

	function next_query_attr(): bool
		%{
		query_attr_idx_++;
		return true;
		%}
};
