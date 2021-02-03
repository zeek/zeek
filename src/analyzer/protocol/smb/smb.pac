%include binpac.pac
%include zeek.pac

%extern{
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/Analyzer.h"

#include "zeek/analyzer/protocol/smb/smb1_events.bif.h"
#include "zeek/analyzer/protocol/smb/smb2_events.bif.h"

#include "zeek/analyzer/protocol/smb/types.bif.h"
#include "zeek/analyzer/protocol/smb/events.bif.h"
#include "zeek/analyzer/protocol/smb/consts.bif.h"

#include "zeek/analyzer/protocol/smb/smb1_com_check_directory.bif.h"
#include "zeek/analyzer/protocol/smb/smb1_com_close.bif.h"
#include "zeek/analyzer/protocol/smb/smb1_com_create_directory.bif.h"
#include "zeek/analyzer/protocol/smb/smb1_com_echo.bif.h"
#include "zeek/analyzer/protocol/smb/smb1_com_logoff_andx.bif.h"
#include "zeek/analyzer/protocol/smb/smb1_com_negotiate.bif.h"
#include "zeek/analyzer/protocol/smb/smb1_com_nt_cancel.bif.h"
#include "zeek/analyzer/protocol/smb/smb1_com_nt_create_andx.bif.h"
#include "zeek/analyzer/protocol/smb/smb1_com_query_information.bif.h"
#include "zeek/analyzer/protocol/smb/smb1_com_read_andx.bif.h"
#include "zeek/analyzer/protocol/smb/smb1_com_session_setup_andx.bif.h"
#include "zeek/analyzer/protocol/smb/smb1_com_transaction.bif.h"
#include "zeek/analyzer/protocol/smb/smb1_com_transaction_secondary.bif.h"
#include "zeek/analyzer/protocol/smb/smb1_com_transaction2.bif.h"
#include "zeek/analyzer/protocol/smb/smb1_com_transaction2_secondary.bif.h"
#include "zeek/analyzer/protocol/smb/smb1_com_tree_connect_andx.bif.h"
#include "zeek/analyzer/protocol/smb/smb1_com_tree_disconnect.bif.h"
#include "zeek/analyzer/protocol/smb/smb1_com_write_andx.bif.h"

#include "zeek/analyzer/protocol/smb/smb2_com_close.bif.h"
#include "zeek/analyzer/protocol/smb/smb2_com_create.bif.h"
#include "zeek/analyzer/protocol/smb/smb2_com_negotiate.bif.h"
#include "zeek/analyzer/protocol/smb/smb2_com_read.bif.h"
#include "zeek/analyzer/protocol/smb/smb2_com_session_setup.bif.h"
#include "zeek/analyzer/protocol/smb/smb2_com_set_info.bif.h"
#include "zeek/analyzer/protocol/smb/smb2_com_tree_connect.bif.h"
#include "zeek/analyzer/protocol/smb/smb2_com_tree_disconnect.bif.h"
#include "zeek/analyzer/protocol/smb/smb2_com_write.bif.h"
#include "zeek/analyzer/protocol/smb/smb2_com_transform_header.bif.h"
%}

analyzer SMB withcontext {
	connection:  SMB_Conn;
	flow:        SMB_Flow;
};

connection SMB_Conn(zeek_analyzer: ZeekAnalyzer) {
	upflow   = SMB_Flow(true);
	downflow = SMB_Flow(false);
};

%include smb-strings.pac
%include smb-common.pac
%include smb-time.pac
%include smb-mailslot.pac
%include smb-pipe.pac
%include smb-gssapi.pac

# SMB1 Commands
%include smb1-com-check-directory.pac
%include smb1-com-close.pac
%include smb1-com-create-directory.pac
%include smb1-com-echo.pac
%include smb1-com-locking-andx.pac
%include smb1-com-logoff-andx.pac
%include smb1-com-negotiate.pac
%include smb1-com-nt-cancel.pac
%include smb1-com-nt-create-andx.pac
%include smb1-com-nt-transact.pac
%include smb1-com-query-information.pac
%include smb1-com-read-andx.pac
%include smb1-com-session-setup-andx.pac
%include smb1-com-transaction-secondary.pac
%include smb1-com-transaction.pac
%include smb1-com-transaction2.pac
%include smb1-com-transaction2-secondary.pac
%include smb1-com-tree-connect-andx.pac
%include smb1-com-tree-disconnect.pac
%include smb1-com-write-andx.pac

# SMB2 Commands
%include smb2-com-close.pac
%include smb2-com-create.pac
%include smb2-com-ioctl.pac
%include smb2-com-lock.pac
%include smb2-com-negotiate.pac
%include smb2-com-read.pac
%include smb2-com-session-setup.pac
%include smb2-com-set-info.pac
%include smb2-com-tree-connect.pac
%include smb2-com-tree-disconnect.pac
%include smb2-com-write.pac
%include smb2-com-transform-header.pac

type uint24 = record {
	byte1 : uint8;
	byte2 : uint8;
	byte3 : uint8;
};

function to_int(num: uint24): uint32
	%{
	return (num->byte1() << 16) | (num->byte2() << 8) | num->byte3();
	%}

type SMB_TCP(is_orig: bool) = record {
	# These are technically NetBIOS fields but it's considered
	# to be SMB directly over TCP.  The fields are essentially
	# the NBSS protocol but it's only used for framing here.
	message_type : uint8;
	len24        : uint24;
	body         : case message_type of {
		# SMB/SMB2 packets are required to use NBSS session messages.
		0       -> nbss : SMB_Protocol_Identifier(is_orig, len);

		# TODO: support more nbss message types?
		default -> skip : bytestring &transient &restofdata;
	};
} &let {
	len : uint32 = to_int(len24);
} &byteorder = littleendian &length=len+4;

type SMB_Protocol_Identifier(is_orig: bool, msg_len: uint32) = record {
	# Sort of cheating by reading this in as an integer instead of a string.
	protocol          : uint32 &byteorder=bigendian;
	smb_1_or_2        : case protocol of {
		SMB1    -> smb1    : SMB_PDU(is_orig, msg_len);
		SMB2    -> smb2    : SMB2_PDU(is_orig);
		# SMB 3.x protocol ID implies use of transform header to support encryption
		SMB3    -> smb3    : SMB2_transform_header;
		default -> unknown : empty;
	};
};

%include smb1-protocol.pac
%include smb2-protocol.pac

flow SMB_Flow(is_orig: bool) {
	flowunit = SMB_TCP(is_orig) withcontext(connection, this);
};
