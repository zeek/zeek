// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"
#include "MOUNT.h"

#include <algorithm>
#include <vector>

#include "BroString.h"
#include "NetVar.h"
#include "XDR.h"
#include "Event.h"

#include "events.bif.h"

using namespace analyzer::rpc;

bool MOUNT_Interp::RPC_BuildCall(RPC_CallInfo* c, const u_char*& buf, int& n)
	{
	if ( c->Program() != 100005 )
		Weird("bad_RPC_program", fmt("%d", c->Program()));

	uint32_t proc = c->Proc();
	// The call arguments, depends on the call type obviously ...
	Val *callarg = nullptr;

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
		callarg = nullptr;
		if ( proc < BifEnum::MOUNT3::PROC_END_OF_PROCS )
			{
			// We know the procedure but haven't implemented it.
			// Otherwise DeliverRPC would complain about
			// excess_RPC.
			n = 0;
			}
		else
			Weird("unknown_MOUNT_request", fmt("%u", proc));

		// Return 1 so that replies to unprocessed calls will still
		// be processed, and the return status extracted.
		return true;
	}

	if ( ! buf )
		{
		// There was a parse error while trying to extract the call
		// arguments. However, we don't know where exactly it
		// happened and whether Vals where already allocated (e.g., a
		// RecordVal was allocated but we failed to fill it). So we
		// Unref() the call arguments, and we are fine.
		Unref(callarg);
		callarg = nullptr;
		return false;
		}

	c->AddVal(callarg); // It's save to AddVal(0).

	return true;
	}

bool MOUNT_Interp::RPC_BuildReply(RPC_CallInfo* c, BifEnum::rpc_status rpc_status,
			       const u_char*& buf, int& n, double start_time,
			       double last_time, int reply_len)
	{
	EventHandlerPtr event = nullptr;
	Val* reply = nullptr;
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
		auto vl = event_common_vl(c, rpc_status, mount_status,
					   start_time, last_time, reply_len, 0);
		analyzer->EnqueueConnEvent(mount_reply_status, std::move(vl));
		}

	if ( ! rpc_success )
		{
		// We set the buffer to NULL, the function that extract the
		// reply from the data stream will then return empty records.
		//
		buf = nullptr;
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
		reply = nullptr;
		n = 0;
		mount_status = BifEnum::MOUNT3::MNT3_OK;
		event = mount_proc_umnt;
		break;

	case BifEnum::MOUNT3::PROC_UMNT_ALL:
		reply = nullptr;
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
			reply = BifType::Enum::MOUNT3::proc_t->GetVal(c->Proc()).release();
			event = mount_proc_not_implemented;
			}
		else
			return false;
	}

	if ( rpc_success && ! buf )
		{
		// There was a parse error. We have to unref the reply. (see
		// also comments in RPC_BuildCall.
		Unref(reply);
		reply = nullptr;
		return false;
		}

	// Note: if reply == 0, it won't be added to the val_list for the
	// event. While we can check for that on the policy layer it's kinda
	// ugly, because it's contrary to the event prototype. But having
	// this optional argument to the event is really helpful. Otherwise I
	// have to let reply point to a RecordVal where all fields are
	// optional and all are set to 0 ...
	if ( event )
		{
		Val *request = c->TakeRequestVal();

		auto vl = event_common_vl(c, rpc_status, mount_status,
					start_time, last_time, reply_len, (bool)request + (bool)reply);

		if ( request )
			vl.emplace_back(AdoptRef{}, request);

		if ( reply )
			vl.emplace_back(AdoptRef{}, reply);

		analyzer->EnqueueConnEvent(event, std::move(vl));
		}
	else
		Unref(reply);
	return true;
	}

zeek::Args MOUNT_Interp::event_common_vl(RPC_CallInfo *c,
				      BifEnum::rpc_status rpc_status,
				      BifEnum::MOUNT3::status_t mount_status,
				      double rep_start_time,
				      double rep_last_time, int reply_len, int extra_elements)
	{
	// Returns a new val_list that already has a conn_val, and mount3_info.
	// These are the first parameters for each mount_* event ...
	zeek::Args vl;
	vl.reserve(2 + extra_elements);
	vl.emplace_back(analyzer->ConnVal());
	auto auxgids = make_intrusive<VectorVal>(zeek::id::index_vec);

	for (size_t i = 0; i < c->AuxGIDs().size(); ++i)
		{
		auxgids->Assign(i, val_mgr->Count(c->AuxGIDs()[i]));
		}

	auto info = make_intrusive<RecordVal>(BifType::Record::MOUNT3::info_t);
	info->Assign(0, BifType::Enum::rpc_status->GetVal(rpc_status));
	info->Assign(1, BifType::Enum::MOUNT3::status_t->GetVal(mount_status));
	info->Assign(2, make_intrusive<Val>(c->StartTime(), TYPE_TIME));
	info->Assign(3, make_intrusive<Val>(c->LastTime() - c->StartTime(), TYPE_INTERVAL));
	info->Assign(4, val_mgr->Count(c->RPCLen()));
	info->Assign(5, make_intrusive<Val>(rep_start_time, TYPE_TIME));
	info->Assign(6, make_intrusive<Val>(rep_last_time - rep_start_time, TYPE_INTERVAL));
	info->Assign(7, val_mgr->Count(reply_len));
	info->Assign(8, val_mgr->Count(c->Uid()));
	info->Assign(9, val_mgr->Count(c->Gid()));
	info->Assign(10, val_mgr->Count(c->Stamp()));
	info->Assign(11, make_intrusive<StringVal>(c->MachineName()));
	info->Assign(12, std::move(auxgids));

	vl.emplace_back(std::move(info));
	return vl;
	}

EnumVal* MOUNT_Interp::mount3_auth_flavor(const u_char*& buf, int& n)
    {
	BifEnum::MOUNT3::auth_flavor_t t = (BifEnum::MOUNT3::auth_flavor_t)extract_XDR_uint32(buf, n);
	return BifType::Enum::MOUNT3::auth_flavor_t->GetVal(t).release();
    }

StringVal* MOUNT_Interp::mount3_fh(const u_char*& buf, int& n)
	{
	int fh_n;
	const u_char* fh = extract_XDR_opaque(buf, n, fh_n, 64);

	if ( ! fh )
		return nullptr;

	return new StringVal(new BroString(fh, fh_n, false));
	}

StringVal* MOUNT_Interp::mount3_filename(const u_char*& buf, int& n)
	{
	int name_len;
	const u_char* name = extract_XDR_opaque(buf, n, name_len);

	if ( ! name )
		return nullptr;

	return new StringVal(new BroString(name, name_len, false));
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

		auto enum_vector = make_intrusive<VectorType>(base_type(TYPE_ENUM));
		auto auth_flavors = make_intrusive<VectorVal>(std::move(enum_vector));

		for ( auto i = 0u; i < auth_flavors_count; ++i )
			auth_flavors->Assign(auth_flavors->Size(),
			                     mount3_auth_flavor(buf, n));

		if ( auth_flavors_count_in_reply > max_auth_flavors )
			// Prevent further "excess RPC" weirds
			n = 0;

		rep->Assign(1, std::move(auth_flavors));
		}
	else
		{
		rep->Assign(0, nullptr);
		rep->Assign(1, nullptr);
		}

	return rep;
	}

MOUNT_Analyzer::MOUNT_Analyzer(Connection* conn)
	: RPC_Analyzer("MOUNT", conn, new MOUNT_Interp(this))
	{
	orig_rpc = resp_rpc = nullptr;
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
