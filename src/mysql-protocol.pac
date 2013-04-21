###
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

enum states {
     CONNECTION_PHASE = 0,
     COMMAND_PHASE = 1
};

type NUL_String = RE/[^\0]*/;

type MySQLPDU(is_orig: bool) = record {
     length1:     uint8;
     # TODO: there are actually 3 bytes for the length here, 
     #       but if I include the others, it won't process.
     #       Currently limited to packets with a length < 256
     # length2:   uint8;
     # length3:	  uint8;
     rest:	  MySQL_Packet(is_orig);
} &let { 
     # Length doesn't inclue the 3 bytes for the length and a byte
     # for the sequence_id, hence +4.
     length: uint32 = (length1 + 4);
     # length: uint32 = ((length3 << 16) + (length2 << 8) + length1 + 4);
}, &length=length;

type MySQL_Packet(is_orig: bool) = record {
     # See MySQLPDU TODO
     unused_length: uint16;
     sequence_id: uint8;
     nul: case (sequence_id) of {
       0 -> initial_packet: Initial_Packet;
       default -> noninitial_packet: Noninitial_Packet(is_orig);
      };
} &byteorder=bigendian;

type Noninitial_Packet(is_orig: bool) = record {
     nul: case(is_orig) of {
         0 -> command_response: Command_Response_Packet;
	 1 -> response_or_request: Response_Or_Request_Packet;
     };
};

type Response_Or_Request_Packet = record {
     nul: case($context.connection.get_state()) of {
	   0 -> handshake_response: Handshake_Response_Packet;
	   1 -> additional_command: Command_Request_Packet;
	   };
};

type Initial_Packet = record {
     nul: case($context.connection.get_state()) of {
       	 0 -> initial_handshake: Initial_Handshake_Packet;
	 1 -> command_request: Command_Request_Packet;
	 };
};
type Initial_Handshake_Packet = record {
     protocol_version: uint8;
     nul: case(protocol_version) of {
     	  10 -> handshake10: Handshake_v10;
	  9  -> handshake9: Handshake_v9;
	  default -> error: ERR_Packet;
     };
};

type Handshake_v10 = record {
     server_version:    NUL_String;
     todo:		bytestring &restofdata;
};

type Handshake_v9 = record {
     todo:	        bytestring &restofdata;
};

type Handshake_Response_Packet = record {
     todo_cap_flags:    uint32;
     todo_max_pkt_size: uint32;
     todo_char_set:	uint8;
     :			bytestring &length=23;
     username:		NUL_String;
     todo:		bytestring &restofdata;
} &byteorder=bigendian;

type Command_Request_Packet = record {
     command:       uint8;
     arg: case(command) of {
        COM_INIT_DB   -> init_db_arg:   bytestring &restofdata;
	COM_QUERY     -> query_arg:     bytestring &restofdata;
	COM_CREATE_DB -> create_db_arg: bytestring &restofdata;
	COM_DROP_DB   -> drop_db_arg:   bytestring &restofdata;
        default       -> no_arg:        empty;
     };
};

type Command_Response_Packet = record {
     pkt_type:	uint8;
     response: case(pkt_type) of {
       0x00 -> data_ok:  OK_Packet;
       0xfe -> data_eof: EOF_Packet;
       0xff -> data_err: ERR_Packet;
     };
};

type OK_Packet = record {
     todo: bytestring &restofdata;
};

type ERR_Packet = record {
     todo: bytestring &restofdata;
};

type EOF_Packet = record {
     todo: bytestring &restofdata;
};

