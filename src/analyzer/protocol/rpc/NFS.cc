// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/rpc/NFS.h"

#include "zeek/zeek-config.h"

#include <utility>
#include <vector>

#include "zeek/Event.h"
#include "zeek/NetVar.h"
#include "zeek/ZeekString.h"
#include "zeek/analyzer/protocol/rpc/XDR.h"
#include "zeek/analyzer/protocol/rpc/events.bif.h"

namespace zeek::analyzer::rpc
	{
namespace detail
	{

bool NFS_Interp::RPC_BuildCall(RPC_CallInfo* c, const u_char*& buf, int& n)
	{
	if ( c->Program() != 100003 )
		Weird("bad_RPC_program", util::fmt("%d", c->Program()));

	uint32_t proc = c->Proc();
	// The call arguments, depends on the call type obviously ...
	ValPtr callarg;

	switch ( proc )
		{
		case BifEnum::NFS3::PROC_NULL:
			break;

		case BifEnum::NFS3::PROC_GETATTR:
			callarg = nfs3_fh(buf, n);
			break;

		case BifEnum::NFS3::PROC_SETATTR:
			callarg = nfs3_sattrargs(buf, n);
			break;

		case BifEnum::NFS3::PROC_LOOKUP:
			callarg = nfs3_diropargs(buf, n);
			break;

		case BifEnum::NFS3::PROC_READ:
			callarg = nfs3_readargs(buf, n);
			break;

		case BifEnum::NFS3::PROC_READLINK:
			callarg = nfs3_fh(buf, n);
			break;

		case BifEnum::NFS3::PROC_SYMLINK:
			callarg = nfs3_symlinkargs(buf, n);
			break;

		case BifEnum::NFS3::PROC_LINK:
			callarg = nfs3_linkargs(buf, n);
			break;

		case BifEnum::NFS3::PROC_WRITE:
			callarg = nfs3_writeargs(buf, n);
			break;

		case BifEnum::NFS3::PROC_CREATE:
			callarg = nfs3_diropargs(buf, n);
			// TODO: implement create attributes. For now we just skip
			// over them.
			n = 0;
			break;

		case BifEnum::NFS3::PROC_MKDIR:
			callarg = nfs3_diropargs(buf, n);
			// TODO: implement mkdir attributes. For now we just skip
			// over them.
			n = 0;
			break;

		case BifEnum::NFS3::PROC_REMOVE:
			callarg = nfs3_diropargs(buf, n);
			break;

		case BifEnum::NFS3::PROC_RMDIR:
			callarg = nfs3_diropargs(buf, n);
			break;

		case BifEnum::NFS3::PROC_RENAME:
			callarg = nfs3_renameopargs(buf, n);
			break;

		case BifEnum::NFS3::PROC_READDIR:
			callarg = nfs3_readdirargs(false, buf, n);
			break;

		case BifEnum::NFS3::PROC_READDIRPLUS:
			callarg = nfs3_readdirargs(true, buf, n);
			break;

		default:
			if ( proc < BifEnum::NFS3::PROC_END_OF_PROCS )
				{
				// We know the procedure but haven't implemented it.
				// Otherwise DeliverRPC would complain about
				// excess_RPC.
				n = 0;
				}
			else
				Weird("unknown_NFS_request", util::fmt("%u", proc));

			// Return 1 so that replies to unprocessed calls will still
			// be processed, and the return status extracted.
			return true;
		}

	if ( ! buf )
		// There was a parse error while trying to extract the call arguments.
		return false;

	c->AddVal(std::move(callarg));

	return true;
	}

bool NFS_Interp::RPC_BuildReply(RPC_CallInfo* c, BifEnum::rpc_status rpc_status, const u_char*& buf,
                                int& n, double start_time, double last_time, int reply_len)
	{
	EventHandlerPtr event = nullptr;
	ValPtr reply;
	BifEnum::NFS3::status_t nfs_status = BifEnum::NFS3::NFS3ERR_OK;
	bool rpc_success = (rpc_status == BifEnum::RPC_SUCCESS);

	// Reply always starts with the NFS status.
	if ( rpc_success )
		{
		if ( n >= 4 )
			nfs_status = (BifEnum::NFS3::status_t)extract_XDR_uint32(buf, n);
		else
			nfs_status = BifEnum::NFS3::NFS3ERR_UNKNOWN;
		}

	if ( nfs_reply_status )
		{
		auto vl = event_common_vl(c, rpc_status, nfs_status, start_time, last_time, reply_len, 0);
		analyzer->EnqueueConnEvent(nfs_reply_status, std::move(vl));
		}

	if ( ! rpc_success )
		{
		// We set the buffer to NULL, the function that extract the
		// reply from the data stream will then return empty records.
		//
		buf = nullptr;
		n = 0;
		}

	switch ( c->Proc() )
		{
		case BifEnum::NFS3::PROC_NULL:
			event = nfs_proc_null;
			break;

		case BifEnum::NFS3::PROC_GETATTR:
			reply = nfs3_fattr(buf, n);
			event = nfs_proc_getattr;
			break;

		case BifEnum::NFS3::PROC_SETATTR:
			reply = nfs3_sattr_reply(buf, n, nfs_status);
			event = nfs_proc_sattr;
			break;

		case BifEnum::NFS3::PROC_LOOKUP:
			reply = nfs3_lookup_reply(buf, n, nfs_status);
			event = nfs_proc_lookup;
			break;

		case BifEnum::NFS3::PROC_READ:
			zeek_uint_t offset;
			offset = c->RequestVal()->AsRecordVal()->GetFieldAs<CountVal>(1);
			reply = nfs3_read_reply(buf, n, nfs_status, offset);
			event = nfs_proc_read;
			break;

		case BifEnum::NFS3::PROC_READLINK:
			reply = nfs3_readlink_reply(buf, n, nfs_status);
			event = nfs_proc_readlink;
			break;

		case BifEnum::NFS3::PROC_SYMLINK:
			reply = nfs3_newobj_reply(buf, n, nfs_status);
			event = nfs_proc_symlink;
			break;

		case BifEnum::NFS3::PROC_LINK:
			reply = nfs3_link_reply(buf, n, nfs_status);
			event = nfs_proc_link;
			break;

		case BifEnum::NFS3::PROC_WRITE:
			reply = nfs3_write_reply(buf, n, nfs_status);
			event = nfs_proc_write;
			break;

		case BifEnum::NFS3::PROC_CREATE:
			reply = nfs3_newobj_reply(buf, n, nfs_status);
			event = nfs_proc_create;
			break;

		case BifEnum::NFS3::PROC_MKDIR:
			reply = nfs3_newobj_reply(buf, n, nfs_status);
			event = nfs_proc_mkdir;
			break;

		case BifEnum::NFS3::PROC_REMOVE:
			reply = nfs3_delobj_reply(buf, n);
			event = nfs_proc_remove;
			break;

		case BifEnum::NFS3::PROC_RMDIR:
			reply = nfs3_delobj_reply(buf, n);
			event = nfs_proc_rmdir;
			break;

		case BifEnum::NFS3::PROC_RENAME:
			reply = nfs3_renameobj_reply(buf, n);
			event = nfs_proc_rename;
			break;

		case BifEnum::NFS3::PROC_READDIR:
			reply = nfs3_readdir_reply(false, buf, n, nfs_status);
			event = nfs_proc_readdir;
			break;

		case BifEnum::NFS3::PROC_READDIRPLUS:
			reply = nfs3_readdir_reply(true, buf, n, nfs_status);
			event = nfs_proc_readdir;
			break;

		default:
			if ( c->Proc() < BifEnum::NFS3::PROC_END_OF_PROCS )
				{
				// We know the procedure but haven't implemented it.
				// Otherwise DeliverRPC would complain about
				// excess_RPC.
				n = 0;
				reply = BifType::Enum::NFS3::proc_t->GetEnumVal(c->Proc());
				event = nfs_proc_not_implemented;
				}
			else
				return false;
		}

	if ( rpc_success && ! buf )
		// There was a parse error.
		return false;

	// Note: if reply == 0, it won't be added to the val_list for the
	// event. While we can check for that on the policy layer it's kinda
	// ugly, because it's contrary to the event prototype. But having
	// this optional argument to the event is really helpful. Otherwise I
	// have to let reply point to a RecordVal where all fields are
	// optional and all are set to 0 ...
	if ( event )
		{
		auto request = c->TakeRequestVal();

		auto vl = event_common_vl(c, rpc_status, nfs_status, start_time, last_time, reply_len,
		                          (bool)request + (bool)reply);

		if ( request )
			vl.emplace_back(std::move(request));

		if ( reply )
			vl.emplace_back(std::move(reply));

		analyzer->EnqueueConnEvent(event, std::move(vl));
		}

	return true;
	}

StringValPtr NFS_Interp::nfs3_file_data(const u_char*& buf, int& n, uint64_t offset, int size)
	{
	int data_n;

	// extract the data, move buf and n
	const u_char* data = extract_XDR_opaque(buf, n, data_n, 1 << 30, true);

	// check whether we have to deliver data to the event
	if ( ! BifConst::NFS3::return_data )
		return nullptr;

	if ( BifConst::NFS3::return_data_first_only && offset != 0 )
		return nullptr;

	// Ok, so we want to return some data
	data_n = std::min(data_n, size);
	data_n = std::min(data_n, int(BifConst::NFS3::return_data_max));

	if ( data && data_n > 0 )
		return make_intrusive<StringVal>(new String(data, data_n, false));

	return nullptr;
	}

Args NFS_Interp::event_common_vl(RPC_CallInfo* c, BifEnum::rpc_status rpc_status,
                                 BifEnum::NFS3::status_t nfs_status, double rep_start_time,
                                 double rep_last_time, int reply_len, int extra_elements)
	{
	// Returns a new val_list that already has a conn_val, and nfs3_info.
	// These are the first parameters for each nfs_* event ...
	Args vl;
	vl.reserve(2 + extra_elements);
	vl.emplace_back(analyzer->ConnVal());
	auto auxgids = make_intrusive<VectorVal>(id::index_vec);

	for ( size_t i = 0; i < c->AuxGIDs().size(); ++i )
		auxgids->Assign(i, val_mgr->Count(c->AuxGIDs()[i]));

	auto info = make_intrusive<RecordVal>(BifType::Record::NFS3::info_t);
	info->Assign(0, BifType::Enum::rpc_status->GetEnumVal(rpc_status));
	info->Assign(1, BifType::Enum::NFS3::status_t->GetEnumVal(nfs_status));
	info->AssignTime(2, c->StartTime());
	info->AssignInterval(3, c->LastTime() - c->StartTime());
	info->Assign(4, c->RPCLen());
	info->AssignTime(5, rep_start_time);
	info->AssignInterval(6, rep_last_time - rep_start_time);
	info->Assign(7, reply_len);
	info->Assign(8, c->Uid());
	info->Assign(9, c->Gid());
	info->Assign(10, c->Stamp());
	info->Assign(11, c->MachineName());
	info->Assign(12, std::move(auxgids));

	vl.emplace_back(std::move(info));
	return vl;
	}

StringValPtr NFS_Interp::nfs3_fh(const u_char*& buf, int& n)
	{
	int fh_n;
	const u_char* fh = extract_XDR_opaque(buf, n, fh_n, 64);

	if ( ! fh )
		return nullptr;

	return make_intrusive<StringVal>(new String(fh, fh_n, false));
	}

RecordValPtr NFS_Interp::nfs3_sattr(const u_char*& buf, int& n)
	{
	auto attrs = make_intrusive<RecordVal>(BifType::Record::NFS3::sattr_t);

	int mode_set_it = extract_XDR_uint32(buf, n);
	if ( mode_set_it )
		attrs->Assign(0, ExtractUint32(buf, n)); // mode

	int uid_set_it = extract_XDR_uint32(buf, n);
	if ( uid_set_it )
		attrs->Assign(1, ExtractUint32(buf, n)); // uid

	int gid_set_it = extract_XDR_uint32(buf, n);
	if ( gid_set_it )
		attrs->Assign(2, ExtractUint32(buf, n)); // gid

	int size_set_it = extract_XDR_uint32(buf, n);
	if ( size_set_it )
		attrs->Assign(3, ExtractTime(buf, n)); // size

	attrs->Assign(4, nfs3_time_how(buf, n)); // time_how

	attrs->Assign(5, nfs3_time_how(buf, n)); // time_how

	return attrs;
	}

RecordValPtr NFS_Interp::nfs3_sattr_reply(const u_char*& buf, int& n,
                                          BifEnum::NFS3::status_t status)
	{
	auto rep = make_intrusive<RecordVal>(BifType::Record::NFS3::sattr_reply_t);

	if ( status == BifEnum::NFS3::NFS3ERR_OK )
		{
		rep->Assign(0, nfs3_pre_op_attr(buf, n));
		rep->Assign(1, nfs3_post_op_attr(buf, n));
		}

	return rep;
	}

RecordValPtr NFS_Interp::nfs3_fattr(const u_char*& buf, int& n)
	{
	auto attrs = make_intrusive<RecordVal>(BifType::Record::NFS3::fattr_t);

	attrs->Assign(0, nfs3_ftype(buf, n)); // file type
	attrs->Assign(1, ExtractUint32(buf, n)); // mode
	attrs->Assign(2, ExtractUint32(buf, n)); // nlink
	attrs->Assign(3, ExtractUint32(buf, n)); // uid
	attrs->Assign(4, ExtractUint32(buf, n)); // gid
	attrs->Assign(5, ExtractUint64(buf, n)); // size
	attrs->Assign(6, ExtractUint64(buf, n)); // used
	attrs->Assign(7, ExtractUint32(buf, n)); // rdev1
	attrs->Assign(8, ExtractUint32(buf, n)); // rdev2
	attrs->Assign(9, ExtractUint64(buf, n)); // fsid
	attrs->Assign(10, ExtractUint64(buf, n)); // fileid
	attrs->Assign(11, ExtractTime(buf, n)); // atime
	attrs->Assign(12, ExtractTime(buf, n)); // mtime
	attrs->Assign(13, ExtractTime(buf, n)); // ctime

	return attrs;
	}

EnumValPtr NFS_Interp::nfs3_time_how(const u_char*& buf, int& n)
	{
	BifEnum::NFS3::time_how_t t = (BifEnum::NFS3::time_how_t)extract_XDR_uint32(buf, n);
	auto rval = BifType::Enum::NFS3::time_how_t->GetEnumVal(t);
	return rval;
	}

EnumValPtr NFS_Interp::nfs3_ftype(const u_char*& buf, int& n)
	{
	BifEnum::NFS3::file_type_t t = (BifEnum::NFS3::file_type_t)extract_XDR_uint32(buf, n);
	auto rval = BifType::Enum::NFS3::file_type_t->GetEnumVal(t);
	return rval;
	}

RecordValPtr NFS_Interp::nfs3_wcc_attr(const u_char*& buf, int& n)
	{
	auto attrs = make_intrusive<RecordVal>(BifType::Record::NFS3::wcc_attr_t);

	attrs->Assign(0, ExtractUint64(buf, n)); // size
	attrs->Assign(1, ExtractTime(buf, n)); // mtime
	attrs->Assign(2, ExtractTime(buf, n)); // ctime

	return attrs;
	}

StringValPtr NFS_Interp::nfs3_filename(const u_char*& buf, int& n)
	{
	int name_len;
	const u_char* name = extract_XDR_opaque(buf, n, name_len);

	if ( ! name )
		return nullptr;

	return make_intrusive<StringVal>(new String(name, name_len, false));
	}

RecordValPtr NFS_Interp::nfs3_diropargs(const u_char*& buf, int& n)
	{
	auto diropargs = make_intrusive<RecordVal>(BifType::Record::NFS3::diropargs_t);

	diropargs->Assign(0, nfs3_fh(buf, n));
	diropargs->Assign(1, nfs3_filename(buf, n));

	return diropargs;
	}

RecordValPtr NFS_Interp::nfs3_symlinkdata(const u_char*& buf, int& n)
	{
	auto symlinkdata = make_intrusive<RecordVal>(BifType::Record::NFS3::symlinkdata_t);

	symlinkdata->Assign(0, nfs3_sattr(buf, n));
	symlinkdata->Assign(1, nfs3_nfspath(buf, n));

	return symlinkdata;
	}

RecordValPtr NFS_Interp::nfs3_renameopargs(const u_char*& buf, int& n)
	{
	auto renameopargs = make_intrusive<RecordVal>(BifType::Record::NFS3::renameopargs_t);

	renameopargs->Assign(0, nfs3_fh(buf, n));
	renameopargs->Assign(1, nfs3_filename(buf, n));
	renameopargs->Assign(2, nfs3_fh(buf, n));
	renameopargs->Assign(3, nfs3_filename(buf, n));

	return renameopargs;
	}

RecordValPtr NFS_Interp::nfs3_post_op_attr(const u_char*& buf, int& n)
	{
	int have_attrs = extract_XDR_uint32(buf, n);

	if ( have_attrs )
		return nfs3_fattr(buf, n);

	return nullptr;
	}

StringValPtr NFS_Interp::nfs3_post_op_fh(const u_char*& buf, int& n)
	{
	int have_fh = extract_XDR_uint32(buf, n);

	if ( have_fh )
		return nfs3_fh(buf, n);

	return nullptr;
	}

RecordValPtr NFS_Interp::nfs3_pre_op_attr(const u_char*& buf, int& n)
	{
	int have_attrs = extract_XDR_uint32(buf, n);

	if ( have_attrs )
		return nfs3_wcc_attr(buf, n);
	return nullptr;
	}

EnumValPtr NFS_Interp::nfs3_stable_how(const u_char*& buf, int& n)
	{
	BifEnum::NFS3::stable_how_t stable = (BifEnum::NFS3::stable_how_t)extract_XDR_uint32(buf, n);
	auto rval = BifType::Enum::NFS3::stable_how_t->GetEnumVal(stable);
	return rval;
	}

RecordValPtr NFS_Interp::nfs3_lookup_reply(const u_char*& buf, int& n,
                                           BifEnum::NFS3::status_t status)
	{
	auto rep = make_intrusive<RecordVal>(BifType::Record::NFS3::lookup_reply_t);

	if ( status == BifEnum::NFS3::NFS3ERR_OK )
		{
		rep->Assign(0, nfs3_fh(buf, n));
		rep->Assign(1, nfs3_post_op_attr(buf, n));
		rep->Assign(2, nfs3_post_op_attr(buf, n));
		}
	else
		{
		rep->Assign(2, nfs3_post_op_attr(buf, n));
		}
	return rep;
	}

RecordValPtr NFS_Interp::nfs3_readargs(const u_char*& buf, int& n)
	{
	auto readargs = make_intrusive<RecordVal>(BifType::Record::NFS3::readargs_t);

	readargs->Assign(0, nfs3_fh(buf, n));
	readargs->Assign(1, ExtractUint64(buf, n)); // offset
	readargs->Assign(2, ExtractUint32(buf, n)); // size

	return readargs;
	}

RecordValPtr NFS_Interp::nfs3_read_reply(const u_char*& buf, int& n, BifEnum::NFS3::status_t status,
                                         zeek_uint_t offset)
	{
	auto rep = make_intrusive<RecordVal>(BifType::Record::NFS3::read_reply_t);

	if ( status == BifEnum::NFS3::NFS3ERR_OK )
		{
		uint32_t bytes_read;

		rep->Assign(0, nfs3_post_op_attr(buf, n));
		bytes_read = extract_XDR_uint32(buf, n);
		rep->Assign(1, bytes_read);
		rep->Assign(2, ExtractBool(buf, n));
		rep->Assign(3, nfs3_file_data(buf, n, offset, bytes_read));
		}
	else
		{
		rep->Assign(0, nfs3_post_op_attr(buf, n));
		}

	return rep;
	}

RecordValPtr NFS_Interp::nfs3_readlink_reply(const u_char*& buf, int& n,
                                             BifEnum::NFS3::status_t status)
	{
	auto rep = make_intrusive<RecordVal>(BifType::Record::NFS3::readlink_reply_t);

	if ( status == BifEnum::NFS3::NFS3ERR_OK )
		{
		rep->Assign(0, nfs3_post_op_attr(buf, n));
		rep->Assign(1, nfs3_nfspath(buf, n));
		}
	else
		{
		rep->Assign(0, nfs3_post_op_attr(buf, n));
		}

	return rep;
	}

RecordValPtr NFS_Interp::nfs3_link_reply(const u_char*& buf, int& n, BifEnum::NFS3::status_t status)
	{
	auto rep = make_intrusive<RecordVal>(BifType::Record::NFS3::link_reply_t);

	if ( status == BifEnum::NFS3::NFS3ERR_OK )
		{
		rep->Assign(0, nfs3_post_op_attr(buf, n));

		// wcc_data
		rep->Assign(1, nfs3_pre_op_attr(buf, n));
		rep->Assign(2, nfs3_post_op_attr(buf, n));
		}

	return rep;
	}

RecordValPtr NFS_Interp::nfs3_symlinkargs(const u_char*& buf, int& n)
	{
	auto symlinkargs = make_intrusive<RecordVal>(BifType::Record::NFS3::symlinkargs_t);

	symlinkargs->Assign(0, nfs3_diropargs(buf, n));
	symlinkargs->Assign(1, nfs3_symlinkdata(buf, n));

	return symlinkargs;
	}

RecordValPtr NFS_Interp::nfs3_sattrargs(const u_char*& buf, int& n)
	{
	auto sattrargs = make_intrusive<RecordVal>(BifType::Record::NFS3::sattrargs_t);

	sattrargs->Assign(0, nfs3_fh(buf, n));
	sattrargs->Assign(1, nfs3_sattr(buf, n));

	return sattrargs;
	}

RecordValPtr NFS_Interp::nfs3_linkargs(const u_char*& buf, int& n)
	{
	auto linkargs = make_intrusive<RecordVal>(BifType::Record::NFS3::linkargs_t);

	linkargs->Assign(0, nfs3_fh(buf, n));
	linkargs->Assign(1, nfs3_diropargs(buf, n));

	return linkargs;
	}

RecordValPtr NFS_Interp::nfs3_writeargs(const u_char*& buf, int& n)
	{
	uint32_t bytes;
	uint64_t offset;
	auto writeargs = make_intrusive<RecordVal>(BifType::Record::NFS3::writeargs_t);

	writeargs->Assign(0, nfs3_fh(buf, n));
	offset = extract_XDR_uint64(buf, n);
	writeargs->Assign(1, offset); // offset
	bytes = extract_XDR_uint32(buf, n);
	writeargs->Assign(2, bytes); // size

	writeargs->Assign(3, nfs3_stable_how(buf, n));
	writeargs->Assign(4, nfs3_file_data(buf, n, offset, bytes));

	return writeargs;
	}

RecordValPtr NFS_Interp::nfs3_write_reply(const u_char*& buf, int& n,
                                          BifEnum::NFS3::status_t status)
	{
	auto rep = make_intrusive<RecordVal>(BifType::Record::NFS3::write_reply_t);

	if ( status == BifEnum::NFS3::NFS3ERR_OK )
		{
		rep->Assign(0, nfs3_pre_op_attr(buf, n));
		rep->Assign(1, nfs3_post_op_attr(buf, n));
		rep->Assign(2, ExtractUint32(buf, n));
		rep->Assign(3, nfs3_stable_how(buf, n));

		// Writeverf. While the RFC says that this should be a fixed
		// length opaque, it specifies the length as 8 bytes, so we
		// can also just as easily extract a uint64.
		rep->Assign(4, ExtractUint64(buf, n));
		}
	else
		{
		rep->Assign(0, nfs3_post_op_attr(buf, n));
		rep->Assign(1, nfs3_pre_op_attr(buf, n));
		}

	return rep;
	}

RecordValPtr NFS_Interp::nfs3_newobj_reply(const u_char*& buf, int& n,
                                           BifEnum::NFS3::status_t status)
	{
	auto rep = make_intrusive<RecordVal>(BifType::Record::NFS3::newobj_reply_t);

	if ( status == BifEnum::NFS3::NFS3ERR_OK )
		{
		int i = 0;
		rep->Assign(0, nfs3_post_op_fh(buf, n));
		rep->Assign(1, nfs3_post_op_attr(buf, n));
		// wcc_data
		rep->Assign(2, nfs3_pre_op_attr(buf, n));
		rep->Assign(3, nfs3_post_op_attr(buf, n));
		}
	else
		{
		rep->Assign(2, nfs3_pre_op_attr(buf, n));
		rep->Assign(3, nfs3_post_op_attr(buf, n));
		}

	return rep;
	}

RecordValPtr NFS_Interp::nfs3_delobj_reply(const u_char*& buf, int& n)
	{
	auto rep = make_intrusive<RecordVal>(BifType::Record::NFS3::delobj_reply_t);

	// wcc_data
	rep->Assign(0, nfs3_pre_op_attr(buf, n));
	rep->Assign(1, nfs3_post_op_attr(buf, n));

	return rep;
	}

RecordValPtr NFS_Interp::nfs3_renameobj_reply(const u_char*& buf, int& n)
	{
	auto rep = make_intrusive<RecordVal>(BifType::Record::NFS3::renameobj_reply_t);

	// wcc_data
	rep->Assign(0, nfs3_pre_op_attr(buf, n));
	rep->Assign(1, nfs3_post_op_attr(buf, n));
	rep->Assign(2, nfs3_pre_op_attr(buf, n));
	rep->Assign(3, nfs3_post_op_attr(buf, n));

	return rep;
	}

RecordValPtr NFS_Interp::nfs3_readdirargs(bool isplus, const u_char*& buf, int& n)
	{
	auto args = make_intrusive<RecordVal>(BifType::Record::NFS3::readdirargs_t);

	args->Assign(0, isplus);
	args->Assign(1, nfs3_fh(buf, n));
	args->Assign(2, ExtractUint64(buf, n)); // cookie
	args->Assign(3, ExtractUint64(buf, n)); // cookieverf
	args->Assign(4, ExtractUint32(buf, n)); // dircount

	if ( isplus )
		args->Assign(5, ExtractUint32(buf, n));

	return args;
	}

RecordValPtr NFS_Interp::nfs3_readdir_reply(bool isplus, const u_char*& buf, int& n,
                                            BifEnum::NFS3::status_t status)
	{
	auto rep = make_intrusive<RecordVal>(BifType::Record::NFS3::readdir_reply_t);

	rep->Assign(0, isplus);

	if ( status == BifEnum::NFS3::NFS3ERR_OK )
		{
		unsigned pos;
		auto entries = make_intrusive<VectorVal>(BifType::Vector::NFS3::direntry_vec_t);

		rep->Assign(1, nfs3_post_op_attr(buf, n)); // dir_attr
		rep->Assign(2, ExtractUint64(buf, n)); // cookieverf

		pos = 1;

		while ( extract_XDR_uint32(buf, n) )
			{
			auto entry = make_intrusive<RecordVal>(BifType::Record::NFS3::direntry_t);
			entry->Assign(0, ExtractUint64(buf, n)); // fileid
			entry->Assign(1, nfs3_filename(buf, n)); // fname
			entry->Assign(2, ExtractUint64(buf, n)); // cookie

			if ( isplus )
				{
				entry->Assign(3, nfs3_post_op_attr(buf, n));
				entry->Assign(4, nfs3_post_op_fh(buf, n));
				}

			entries->Assign(pos, std::move(entry));
			pos++;
			}

		rep->Assign(3, entries);
		rep->Assign(4, ExtractBool(buf, n)); // eof
		}
	else
		{
		rep->Assign(1, nfs3_post_op_attr(buf, n));
		}

	return rep;
	}

uint32_t NFS_Interp::ExtractUint32(const u_char*& buf, int& n)
	{
	return extract_XDR_uint32(buf, n);
	}

uint64_t NFS_Interp::ExtractUint64(const u_char*& buf, int& n)
	{
	return extract_XDR_uint64(buf, n);
	}

double NFS_Interp::ExtractTime(const u_char*& buf, int& n)
	{
	return extract_XDR_time(buf, n);
	}

double NFS_Interp::ExtractInterval(const u_char*& buf, int& n)
	{
	return double(extract_XDR_uint32(buf, n));
	}

bool NFS_Interp::ExtractBool(const u_char*& buf, int& n)
	{
	return extract_XDR_uint32(buf, n);
	}

	} // namespace detail

NFS_Analyzer::NFS_Analyzer(Connection* conn)
	: RPC_Analyzer("NFS", conn, new detail::NFS_Interp(this))
	{
	orig_rpc = resp_rpc = nullptr;
	}

void NFS_Analyzer::Init()
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
