### Connection phase
#
# All information is from the MySQL internals documentation at:
# <http://dev.mysql.com/doc/internals/en/connection-phase.html>
#
###

enum capability_flags {
     CLIENT_LONG_PASSWORD		   = 0x00000001,
     CLIENT_FOUND_ROWS			   = 0x00000002,
     CLIENT_LONG_FLAG			   = 0x00000004,
     CLIENT_CONNECT_WITH_DB		   = 0x00000008,
     CLIENT_NO_SCHEMA			   = 0x00000010,
     CLIENT_COMPRESS			   = 0x00000020,
     CLIENT_ODBC			   = 0x00000040,
     CLIENT_LOCAL_FILES			   = 0x00000080,
     CLIENT_IGNORE_SPACE		   = 0x00000100,
     CLIENT_PROTOCOL_41			   = 0x00000200,
     CLIENT_INTERACTIVE			   = 0x00000400,
     CLIENT_SSL				   = 0x00000800,
     CLIENT_IGNORE_SIGPIPE		   = 0x00001000,
     CLIENT_TRANSACTIONS		   = 0x00002000,
     CLIENT_RESERVED			   = 0x00004000,
     CLIENT_SECURE_CONNECTION		   = 0x00008000,
     CLIENT_MULTI_STATEMENTS		   = 0x00010000,
     CLIENT_MULTI_RESULTS		   = 0x00020000,
     CLIENT_PS_MULTI_RESULTS		   = 0x00040000,
     CLIENT_PLUGIN_AUTH			   = 0x00080000,
     CLIENT_CONNECT_ATTRS		   = 0x00100000,
     CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000
};

enum status_flags {
     SERVER_STATUS_IN_TRANS             = 0x0001,
     SERVER_STATUS_AUTOCOMMIT           = 0x0002,
     SERVER_MORE_RESULTS_EXIST          = 0x0008,
     SERVER_STATUS_NO_GOOD_INDEX_USED   = 0x0010,
     SERVER_STATUS_NO_INDEX_USED        = 0x0020,
     SERVER_STATUS_CURSOR_EXISTS        = 0x0040,
     SERVER_STATUS_LAST_ROW_SENT        = 0x0080,
     SERVER_STATUS_DB_DROPPED           = 0x0100,
     SERVER_STATUS_NO_BACKSLASH_ESCAPES = 0x0200,
     SERVER_STATUS_METADATA_CHANGED     = 0x0400,
     SERVER_QUERY_WAS_SLOW              = 0x0800,
     SERVER_PS_OUT_PARAMS               = 0x1000
};

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

refine connection MySQL_Conn += {
       %member{
		int conn_phase_done_;
       %}
       
       %init{
		conn_phase_done_=0;
       %}

       function conn_phase_done() : int %{ return conn_phase_done_; %}
};       


type FixedLengthInteger1 = record {data: bytestring &length=1;} &byteorder=littleendian, &let {value: int = bytestring_to_int(data, 10);};
type FixedLengthInteger2 = record {data: bytestring &length=2;} &byteorder=littleendian, &let {value: int = bytestring_to_int(data, 10);};
type FixedLengthInteger3 = record {data: bytestring &length=3;} &byteorder=littleendian, &let {value: int = bytestring_to_int(data, 10);};
type FixedLengthInteger4 = record {data: bytestring &length=4;} &byteorder=littleendian, &let {value: int = bytestring_to_int(data, 10);};
#type FixedLengthInteger6 = bytestring &length=6 &byteorder=littlendian;
type FixedLengthInteger8 = record {data: bytestring &length=8;} &byteorder=littleendian, &let {value: int = bytestring_to_int(data, 10);};
type LengthEncodedInteger = record {
     length: FixedLengthInteger1;
     tmp:    case length.value of {
     	  0xfc    -> int2: FixedLengthInteger2;
	  0xfd    -> int3: FixedLengthInteger3;
	  0xfe    -> int8: FixedLengthInteger8;
     };
} &let {
  value: int = (length.value < 0xfc) ? length.value : (length.value == 0xfc) ? int2.value : (length.value == 0xfd) ? int3.value : int8.value;
};

type RestOfLine = RE/.*/;

type MySQLPDU(is_orig: bool) = record {
     length:      FixedLengthInteger3;
     sequence_id: FixedLengthInteger1;
     : case $context.connection.conn_phase_done() of {
         0 -> conn_packet: Connection_Packet(is_orig);
	 1 -> cmd_packet:  Command_Packet(is_orig);
     };
};

type Connection_Packet(is_orig: bool) = record {
     : case is_orig of {
       0 -> initial_handshake_packet: Initial_Handshake_Packet;
       1 -> handshake_response_packet: Handshake_Response_Packet;
     };
};

type Handshake_Response_Packet = record {
     #todo:		       bytestring &restofdata;
};

type Initial_Handshake_Packet = record {
     protocol_version: FixedLengthInteger1;
     :   case protocol_version.value of {
     	  0x0a -> handshake10: Handshake_v10;
	  0x09 -> handshake9: Handshake_v9;
     };
};

type Handshake_v10 = record {
     server_version: 	      bytestring &oneline;
     connection_id:  	      FixedLengthInteger4;
     auth_plugin_data_part_1: bytestring &length=8;
     :			      FixedLengthInteger1;
     capability_flags:	      FixedLengthInteger2;
     #todo:		      bytestring &restofdata;
};

type Handshake_v9 = record {
     server_version: bytestring &oneline;
     connection_id:  FixedLengthInteger4;
     scramble:       bytestring &oneline;
};

type Command_Packet(is_orig: bool) = record {
     : case is_orig of {
       0 -> command_response: Command_Response_Packet;
       1 -> command_request: Command_Request_Packet;
     };
};

type Command_Request_Packet = record {
     command:       FixedLengthInteger1;
};

type OK_Packet(expect_status: bool, expect_warnings: bool) = record {
     affected_rows:  LengthEncodedInteger;
     last_insert_id: LengthEncodedInteger;
     tmp:   case expect_status of {
     	true    -> status_flags: FixedLengthInteger2;
     };
     tmp2:   case expect_warnings of {
     	true    -> warnings: FixedLengthInteger2;
     };
     # info:	bytestring &restofdata;
};

type ERR_Packet(expect_warnings: bool) = record {
     error_code: FixedLengthInteger2;
     tmp:  case expect_warnings of {
        true   -> sql_state: SQLState;
     };
     # error_message: bytestring &restofdata;
};

type EOF_Packet(expect_warnings: bool) = record {
     tmp: case expect_warnings of {
        true    -> warning_count: FixedLengthInteger2;
     };
     tmp2: case expect_warnings of {
        true    -> status_flags: FixedLengthInteger2;
     };
};

type SQLState = record {
     : bytestring &length=1;
     sql_state: bytestring &length=5;
};

type Command_Response_Packet = record {
     header:	  FixedLengthInteger1;
     tmp:    case header.value of {
     	  0x00 -> data_ok:  OK_Packet(1, 1);
	  0xfe -> data_eof: EOF_Packet(1);
	  0xff -> data_err: ERR_Packet(1);
     };
};
