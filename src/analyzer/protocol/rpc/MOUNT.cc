// See the file "COPYING" in the main distribution directory for copyright.

#include <algorithm>
#include <vector>

#include "bro-config.h"

#include "NetVar.h"
#include "XDR.h"
#include "MOUNT.h"
#include "Event.h"

#include "events.bif.h"

using namespace analyzer::rpc;

int MOUNT_Interp::RPC_BuildCall(RPC_CallInfo* c, const u_char*& buf, int& n)
	{
	if ( c->Program() != 100005 )
		Weird(fmt("bad_RPC_program (%d)", c->Program()));

	uint32 proc = c->Proc();
	// The call arguments, depends on the call type obviously ...
	Val *callarg = 0;

	switch ( proc ) {
		case BifEnum::MOUNT3::PROC_NULL:
		break;

	case BifEnum::MOUNT3::PROC_MNT:
		callarg = mount3_dirmntargs(buf, n);
		break;

	case BifEnum::MOUNT3::PROC_UMNT:
		callarg = mount3_dirmntargs(buf, n);
		break;

	case BifEnum::MOUNT3::PROC_UMNT_ALL:
		callarg = mount3_dirmntargs(buf, n);
		break;

	default:
		callarg = 0;
		if ( proc < BifEnum::MOUNT3::PROC_END_OF_PROCS )
			{
			// We know the procedure but haven't implemented it.
			// Otherwise DeliverRPC would complain about
			// excess_RPC.
			n = 0;
			}
		else
			Weird(fmt("unknown_MOUNT_request(%u)", proc));

		// Return 1 so that replies to unprocessed calls will still
		// be processed, and the return status extracted.
		return 1;
	}

	if ( ! buf )
		{
		// There was a parse error while trying to extract the call
		// arguments. However, we don't know where exactly it
		// happened and whether Vals where already allocated (e.g., a
		// RecordVal was allocated but we failed to fill it). So we
		// Unref() the call arguments, and we are fine.
		Unref(callarg);
		callarg = 0;
		return 0;
		}

	c->AddVal(callarg); // It's save to AddVal(0).

	return 1;
	}

int MOUNT_Interp::RPC_BuildReply(RPC_CallInfo* c, BifEnum::rpc_status rpc_status,
			       const u_char*& buf, int& n, double start_time,
			       double last_time, int reply_len)
	{
	EventHandlerPtr event = 0;
	Val* reply = 0;
	BifEnum::MOUNT3::status_t mount_status = BifEnum::MOUNT3::MNT3_OK;
	bool rpc_success = ( rpc_status == BifEnum::RPC_SUCCESS );

	// Reply always starts with the MOUNT status.
	if ( rpc_success )
		{
		if ( n >= 4 )
			mount_status = (BifEnum::MOUNT3::status_t)extract_XDR_uint32(buf, n);
		else
			mount_status = BifEnum::MOUNT3::MOUNT3ERR_UNKNOWN;
		}

	if ( mount_reply_status )
		{
		val_list* vl = event_common_vl(c, rpc_status, mount_status,
					   start_time, last_time, reply_len);
		analyzer->ConnectionEvent(mount_reply_status, vl);
		}

	if ( ! rpc_success )
		{
		// We set the buffer to NULL, the function that extract the
		// reply from the data stream will then return empty records.
		//
		buf = NULL;
		n = 0;
		}

	switch ( c->Proc() ) {
	case BifEnum::MOUNT3::PROC_NULL:
		event = mount_proc_null;
		break;

	case BifEnum::MOUNT3::PROC_MNT:
		reply = mount3_mnt_reply(buf, n, mount_status);
		event = mount_proc_mnt;
		break;

	case BifEnum::MOUNT3::PROC_UMNT:
		reply = 0;
		n = 0;
		mount_status = BifEnum::MOUNT3::MNT3_OK;
		event = mount_proc_umnt;
		break;

	case BifEnum::MOUNT3::PROC_UMNT_ALL:
		reply = 0;
		n = 0;
		mount_status = BifEnum::MOUNT3::MNT3_OK;
		event = mount_proc_umnt;
		break;

	default:
		if ( c->Proc() < BifEnum::MOUNT3::PROC_END_OF_PROCS )
			{
			// We know the procedure but haven't implemented it.
			// Otherwise DeliverRPC would complain about
			// excess_RPC.
			n = 0;
			reply = new EnumVal(c->Proc(), BifType::Enum::MOUNT3::proc_t);
			event = mount_proc_not_implemented;
			}
		else
			return 0;
	}

	if ( rpc_success && ! buf )
		{
		// There was a parse error. We have to unref the reply. (see
		// also comments in RPC_BuildCall.
		Unref(reply);
		reply = 0;
		return 0;
		}

	// Note: if reply == 0, it won't be added to the val_list for the
	// event. While we can check for that on the policy layer it's kinda
	// ugly, because it's contrary to the event prototype. But having
	// this optional argument to the event is really helpful. Otherwise I
	// have to let reply point to a RecordVal where all fields are
	// optional and all are set to 0 ...
	if ( event )
		{
		val_list* vl = event_common_vl(c, rpc_status, mount_status,
					start_time, last_time, reply_len);

		Val *request = c->TakeRequestVal();

		if ( request )
			vl->append(request);

		if ( reply )
			vl->append(reply);

		analyzer->ConnectionEvent(event, vl);
		}
	else
		Unref(reply);
	return 1;
	}

val_list* MOUNT_Interp::event_common_vl(RPC_CallInfo *c, 
		      BifEnum::rpc_status rpc_status,
				      BifEnum::MOUNT3::status_t mount_status,
				      double rep_start_time,
				      double rep_last_time, int reply_len)
	{
	// Returns a new val_list that already has a conn_val, and mount3_info.
	// These are the first parameters for each mount_* event ...
	val_list *vl = new val_list;
	vl->append(analyzer->BuildConnVal());
	VectorVal* auxgids = new VectorVal(internal_type("index_vec")->AsVectorType());

	for (size_t i = 0; i < c->AuxGIDs().size(); ++i)
		{
		auxgids->Assign(i, new Val(c->AuxGIDs()[i], TYPE_COUNT));
		}

	RecordVal* info = new RecordVal(BifType::Record::MOUNT3::info_t);
	info->Assign(0, new EnumVal(rpc_status, BifType::Enum::rpc_status));
	info->Assign(1, new EnumVal(mount_status, BifType::Enum::MOUNT3::status_t));
	info->Assign(2, new Val(c->StartTime(), TYPE_TIME));
	info->Assign(3, new Val(c->LastTime() - c->StartTime(), TYPE_INTERVAL));
	info->Assign(4, new Val(c->RPCLen(), TYPE_COUNT));
	info->Assign(5, new Val(rep_start_time, TYPE_TIME));
	info->Assign(6, new Val(rep_last_time - rep_start_time, TYPE_INTERVAL));
	info->Assign(7, new Val(reply_len, TYPE_COUNT));
	info->Assign(8, new Val(c->Uid(), TYPE_COUNT));
	info->Assign(9, new Val(c->Gid(), TYPE_COUNT));
	info->Assign(10, new Val(c->Stamp(), TYPE_COUNT));
	info->Assign(11, new StringVal(c->MachineName()));
	info->Assign(12, auxgids);

	vl->append(info);
	return vl;
	}

EnumVal* MOUNT_Interp::mount3_auth_flavor(const u_char*& buf, int& n)
    {
	BifEnum::MOUNT3::auth_flavor_t t = (BifEnum::MOUNT3::auth_flavor_t)extract_XDR_uint32(buf, n);
	return new EnumVal(t, BifType::Enum::MOUNT3::auth_flavor_t);
    }

StringVal* MOUNT_Interp::mount3_fh(const u_char*& buf, int& n)
	{
	int fh_n;
	const u_char* fh = extract_XDR_opaque(buf, n, fh_n, 64);

	if ( ! fh )
		return 0;

	return new StringVal(new BroString(fh, fh_n, 0));
	}

StringVal* MOUNT_Interp::mount3_filename(const u_char*& buf, int& n)
	{
	int name_len;
	const u_char* name = extract_XDR_opaque(buf, n, name_len);

	if ( ! name )
		return 0;

	return new StringVal(new BroString(name, name_len, 0));
	}

RecordVal* MOUNT_Interp::mount3_dirmntargs(const u_char*& buf, int& n)
	{
	RecordVal* dirmntargs = new RecordVal(BifType::Record::MOUNT3::dirmntargs_t);
	dirmntargs->Assign(0, mount3_filename(buf, n));
	return dirmntargs;
	}

RecordVal* MOUNT_Interp::mount3_mnt_reply(const u_char*& buf, int& n,
		     BifEnum::MOUNT3::status_t status)
	{
	RecordVal* rep = new RecordVal(BifType::Record::MOUNT3::mnt_reply_t);

	if ( status == BifEnum::MOUNT3::MNT3_OK )
		{
		rep->Assign(0, mount3_fh(buf,n));

		auto auth_flavors_count_in_reply =  extract_XDR_uint32(buf, n);
		auto auth_flavors_count = auth_flavors_count_in_reply;
		const auto max_auth_flavors = 32u;

		if ( auth_flavors_count_in_reply > max_auth_flavors )
			{
			Weird("excessive_MNT_auth_flavors");
			auth_flavors_count = max_auth_flavors;
			}

		VectorType* enum_vector = new VectorType(base_type(TYPE_ENUM));
		VectorVal* auth_flavors = new VectorVal(enum_vector);
		Unref(enum_vector);

		for ( auto i = 0u; i < auth_flavors_count; ++i )
			auth_flavors->Assign(auth_flavors->Size(),
			                     mount3_auth_flavor(buf, n));

		if ( auth_flavors_count_in_reply > max_auth_flavors )
			// Prevent further "excess RPC" weirds
			n = 0;

		rep->Assign(1, auth_flavors);
		}
	else
		{
		rep->Assign(0, 0);
		rep->Assign(1, 0);
		}

	return rep;
	}

MOUNT_Analyzer::MOUNT_Analyzer(Connection* conn)
	: RPC_Analyzer("MOUNT", conn, new MOUNT_Interp(this))
	{
	orig_rpc = resp_rpc = 0;
	}

void MOUNT_Analyzer::Init()
	{
	RPC_Analyzer::Init();

	if ( Conn()->ConnTransport() == TRANSPORT_TCP )
		{
		orig_rpc = new Contents_RPC(Conn(), true, interp);
		resp_rpc = new Contents_RPC(Conn(), false, interp);
		AddSupportAnalyzer(orig_rpc);
		AddSupportAnalyzer(resp_rpc);
		}
	}
