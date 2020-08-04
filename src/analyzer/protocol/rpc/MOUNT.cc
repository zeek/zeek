// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"
#include "MOUNT.h"

#include <algorithm>
#include <vector>

#include "ZeekString.h"
#include "NetVar.h"
#include "XDR.h"
#include "Event.h"

#include "events.bif.h"

namespace zeek::analyzer::rpc {
namespace detail {

bool MOUNT_Interp::RPC_BuildCall(RPC_CallInfo* c, const u_char*& buf, int& n)
	{
	if ( c->Program() != 100005 )
		Weird("bad_RPC_program", fmt("%d", c->Program()));

	uint32_t proc = c->Proc();
	// The call arguments, depends on the call type obviously ...
	zeek::RecordValPtr callarg;

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
		// There was a parse error while trying to extract the call arguments.
		return false;

	c->AddVal(callarg);
	return true;
	}

bool MOUNT_Interp::RPC_BuildReply(RPC_CallInfo* c, BifEnum::rpc_status rpc_status,
			       const u_char*& buf, int& n, double start_time,
			       double last_time, int reply_len)
	{
	zeek::EventHandlerPtr event = nullptr;
	zeek::ValPtr reply;
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
		n = 0;
		mount_status = BifEnum::MOUNT3::MNT3_OK;
		event = mount_proc_umnt;
		break;

	case BifEnum::MOUNT3::PROC_UMNT_ALL:
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
			reply = zeek::BifType::Enum::MOUNT3::proc_t->GetEnumVal(c->Proc());
			event = mount_proc_not_implemented;
			}
		else
			return false;
	}

	if ( rpc_success && ! buf )
		{
		// There was a parse error.
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
		auto request = c->TakeRequestVal();

		auto vl = event_common_vl(c, rpc_status, mount_status,
					start_time, last_time, reply_len, (bool)request + (bool)reply);

		if ( request )
			vl.emplace_back(std::move(request));

		if ( reply )
			vl.emplace_back(reply);

		analyzer->EnqueueConnEvent(event, std::move(vl));
		}

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
	auto auxgids = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);

	for (size_t i = 0; i < c->AuxGIDs().size(); ++i)
		{
		auxgids->Assign(i, zeek::val_mgr->Count(c->AuxGIDs()[i]));
		}

	auto info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::MOUNT3::info_t);
	info->Assign(0, zeek::BifType::Enum::rpc_status->GetEnumVal(rpc_status));
	info->Assign(1, zeek::BifType::Enum::MOUNT3::status_t->GetEnumVal(mount_status));
	info->Assign(2, zeek::make_intrusive<zeek::TimeVal>(c->StartTime()));
	info->Assign(3, zeek::make_intrusive<zeek::IntervalVal>(c->LastTime() - c->StartTime()));
	info->Assign(4, zeek::val_mgr->Count(c->RPCLen()));
	info->Assign(5, zeek::make_intrusive<zeek::TimeVal>(rep_start_time));
	info->Assign(6, zeek::make_intrusive<zeek::IntervalVal>(rep_last_time - rep_start_time));
	info->Assign(7, zeek::val_mgr->Count(reply_len));
	info->Assign(8, zeek::val_mgr->Count(c->Uid()));
	info->Assign(9, zeek::val_mgr->Count(c->Gid()));
	info->Assign(10, zeek::val_mgr->Count(c->Stamp()));
	info->Assign(11, zeek::make_intrusive<zeek::StringVal>(c->MachineName()));
	info->Assign(12, std::move(auxgids));

	vl.emplace_back(std::move(info));
	return vl;
	}

zeek::EnumValPtr MOUNT_Interp::mount3_auth_flavor(const u_char*& buf, int& n)
    {
	BifEnum::MOUNT3::auth_flavor_t t = (BifEnum::MOUNT3::auth_flavor_t)extract_XDR_uint32(buf, n);
	auto rval = zeek::BifType::Enum::MOUNT3::auth_flavor_t->GetEnumVal(t);
	return rval;
    }

zeek::StringValPtr MOUNT_Interp::mount3_fh(const u_char*& buf, int& n)
	{
	int fh_n;
	const u_char* fh = extract_XDR_opaque(buf, n, fh_n, 64);

	if ( ! fh )
		return nullptr;

	return zeek::make_intrusive<zeek::StringVal>(new zeek::String(fh, fh_n, false));
	}

zeek::StringValPtr MOUNT_Interp::mount3_filename(const u_char*& buf, int& n)
	{
	int name_len;
	const u_char* name = extract_XDR_opaque(buf, n, name_len);

	if ( ! name )
		return nullptr;

	return zeek::make_intrusive<zeek::StringVal>(new zeek::String(name, name_len, false));
	}

zeek::RecordValPtr MOUNT_Interp::mount3_dirmntargs(const u_char*& buf, int& n)
	{
	auto dirmntargs = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::MOUNT3::dirmntargs_t);
	dirmntargs->Assign(0, mount3_filename(buf, n));
	return dirmntargs;
	}

zeek::RecordValPtr MOUNT_Interp::mount3_mnt_reply(const u_char*& buf, int& n,
                                                  BifEnum::MOUNT3::status_t status)
	{
	auto rep = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::MOUNT3::mnt_reply_t);

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

		auto enum_vector = zeek::make_intrusive<zeek::VectorType>(zeek::base_type(zeek::TYPE_ENUM));
		auto auth_flavors = zeek::make_intrusive<zeek::VectorVal>(std::move(enum_vector));

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

} // namespace detail

MOUNT_Analyzer::MOUNT_Analyzer(zeek::Connection* conn)
	: RPC_Analyzer("MOUNT", conn, new detail::MOUNT_Interp(this))
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

} // namespace zeek::analyzer::rpc
