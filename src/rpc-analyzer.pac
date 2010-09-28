# $Id:$

########################################
# Protocol Syntax.

%include rpc-protocol.pac

########################################
# Connections and flows.

# External headers (placed outside the "binpac" namespace).
%extern{
#include <map>
using namespace std;
%}

# Extensible function for building a Bro Val for the RPC call.
# See portmap-connection.pac.
function RPC_BuildCallVal(call: RPC_Call): BroVal =
	case RPC_Service(call) of {
		default		-> NULL;
	};

# Adding extra let-fields to type RPC_Call.
refine typeattr RPC_Call += &let {
	start_time: double = network_time();

	# Build the Bro Val.
	call_val: BroVal = RPC_BuildCallVal(this);

	action_call: bool = $context.flow.ProcessCall(this);
};

# ... and to RPC_Reply.
refine typeattr RPC_Reply += &let {
	status = RPC_Status(this);
	action_reply: bool = $context.flow.ProcessReply(this);
};

# RPC status in Bro (this is a repeat of enum rpc_status in const.bif :-().
enum EnumRPCStatus {
	RPC_STATUS_SUCCESS	= 0,
	RPC_STATUS_PROG_UNAVAIL	= 1,
	RPC_STATUS_PROG_MISMATCH= 2,
	RPC_STATUS_PROC_UNAVAIL	= 3,
	RPC_STATUS_GARBAGE_ARGS	= 4,
	RPC_STATUS_SYSTEM_ERR	= 5,
	RPC_STATUS_TIMEOUT	= 6,
	RPC_STATUS_MISMATCH	= 7,
	RPC_STATUS_AUTH_ERROR	= 8,
	RPC_STATUS_UNKNOWN_ERROR = 9,
};

function RPC_Status(reply: RPC_Reply): EnumRPCStatus =
	case reply.stat of {
		MSG_ACCEPTED	-> reply.areply.stat;
		MSG_DENIED	-> case reply.rreply.stat of {
			RPC_MISMATCH	-> RPC_STATUS_MISMATCH;
			AUTH_ERROR	-> RPC_STATUS_AUTH_ERROR;
		};
	};

# An RPC interpreter.
connection RPC_Conn(bro_analyzer: BroAnalyzer) {
	upflow = RPC_Flow(true);
	downflow = RPC_Flow(false);

	# Returns the call corresponding to the xid. Returns
	# NULL if not found.
	function FindCall(xid: uint32): RPC_Call
		%{
		RPC_CallTable::const_iterator it = call_table.find(xid);
		return it == call_table.end() ? 0 : it->second;
		%}

	function NewCall(xid: uint32, call: RPC_Call): bool
		%{
		if ( call_table.find(xid) != call_table.end() )
			{
			// Compare retransmission with the original.
			RPC_Call* orig_call = call_table[xid];
			if ( RPC_CompareRexmit(orig_call, call) )
				Weird("RPC_rexmit_inconsistency");
			return false;
			}
		else
			{
			// Add reference count to msg.
			call->msg()->Ref();
			call_table[xid] = call;
			return true;
			}
		%}

	# Returns true if different.
	function RPC_CompareRexmit(orig_call: RPC_Call, new_call: RPC_Call): bool
		%{
		if ( ${orig_call.msg.length} != ${new_call.msg.length} )
			return true;

		return memcmp(${orig_call.msg_source_data}.begin(),
		              ${new_call.msg_source_data}.begin(),
		              ${orig_call.msg.length}) != 0;
		%}

	function FinishCall(call: RPC_Call): void
		%{
		call_table.erase(call->msg()->xid());
		Unref(call->msg());
		%}

	function Timeout(): void
		%{
		for ( RPC_CallTable::const_iterator it = call_table.begin();
		      it != call_table.end(); ++it )
			{
			RPC_Call* call = it->second;
			RPC_CallFailed(this, call, RPC_STATUS_TIMEOUT);
			Unref(call->msg());
			}

		call_table.clear();
		%}

	function Weird(msg: string): void
		%{
		bro_analyzer()->Weird(msg.c_str());
		%}

	%member{
		typedef ::std::map<uint32, RPC_Call*> RPC_CallTable;
		RPC_CallTable call_table;
	%}
};

# A virtual RPC flow.
flow RPC_Flow (is_orig: bool) {
	# An RPC flow consists of RPC_Message datagrams.
	datagram = RPC_Message withcontext (connection, this);

	function ProcessCall(call: RPC_Call): bool
		%{
		if ( ! is_orig() )
			Weird("responder_RPC_call");
		return true;
		%}

	function ProcessReply(reply: RPC_Reply): bool
		%{
		if ( is_orig() )
			Weird("originator_RPC_reply");

		RPC_Call* call = reply->call();
		if ( ! call )
			{
			Weird("unpaired_RPC_response");
			return false;
			}

		bro_event_rpc_call(connection()->bro_analyzer(),
		                   connection()->bro_analyzer()->Conn(),
		                   call->prog(),
		                   call->vers(),
		                   call->proc(),
		                   reply->status(),
		                   call->start_time(),
		                   call->msg()->length(),
		                   reply->msg()->length());

		if ( ! reply->success() )
			RPC_CallFailed(connection(), call, reply->status());

		connection()->FinishCall(call);

		return true;
		%}

	function Weird(msg: string): void
		%{
		connection()->Weird(msg);
		%}

#	TODO: deal with exceptions
#	exception(e: Exception)
#		{
#		Weird(string("bad RPC: ") + e.msg());
#		}
};

# Extensible function for handling failed (rejected/timeout) RPC calls.
function RPC_CallFailed(connection: RPC_Conn,
                        call: RPC_Call,
                        status: EnumRPCStatus): bool =
	case RPC_Service(call) of {
		default		-> false;
	};
