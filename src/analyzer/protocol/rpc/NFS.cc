// See the file "COPYING" in the main distribution directory for copyright.

#include <algorithm>

#include "config.h"

#include "NetVar.h"
#include "XDR.h"
#include "NFS.h"
#include "Event.h"

#include "events.bif.h"

using namespace analyzer::rpc;

int NFS_Interp::RPC_BuildCall(RPC_CallInfo* c, const u_char*& buf, int& n)
	{
	if ( c->Program() != 100003 )
		Weird(fmt("bad_RPC_program (%d)", c->Program()));

	uint32 proc = c->Proc();
	// The call arguments, depends on the call type obviously ...
	Val *callarg = 0;

	switch ( proc ) {
	case BifEnum::NFS3::PROC_NULL:
		break;

	case BifEnum::NFS3::PROC_GETATTR:
		callarg = nfs3_fh(buf, n);
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

	case BifEnum::NFS3::PROC_READDIR:
		callarg = nfs3_readdirargs(false, buf, n);
		break;

	case BifEnum::NFS3::PROC_READDIRPLUS:
		callarg = nfs3_readdirargs(true, buf, n);
		break;

	default:
		callarg = 0;
		if ( proc < BifEnum::NFS3::PROC_END_OF_PROCS )
			{
			// We know the procedure but haven't implemented it.
			// Otherwise DeliverRPC would complain about
			// excess_RPC.
			n = 0;
			}
		else
			Weird(fmt("unknown_NFS_request(%u)", proc));

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

int NFS_Interp::RPC_BuildReply(RPC_CallInfo* c, BifEnum::rpc_status rpc_status,
			       const u_char*& buf, int& n, double start_time,
			       double last_time, int reply_len)
	{
	EventHandlerPtr event = 0;
	Val *reply = 0;
	BifEnum::NFS3::status_t nfs_status = BifEnum::NFS3::NFS3ERR_OK;
	bool rpc_success = ( rpc_status == BifEnum::RPC_SUCCESS );

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
		val_list* vl = event_common_vl(c, rpc_status, nfs_status,
					       start_time, last_time, reply_len);
		analyzer->ConnectionEvent(nfs_reply_status, vl);
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
	case BifEnum::NFS3::PROC_NULL:
		event = nfs_proc_null;
		break;

	case BifEnum::NFS3::PROC_GETATTR:
		reply = nfs3_fattr(buf, n);
		event = nfs_proc_getattr;
		break;

	case BifEnum::NFS3::PROC_LOOKUP:
		reply = nfs3_lookup_reply(buf, n, nfs_status);
		event = nfs_proc_lookup;
		break;

	case BifEnum::NFS3::PROC_READ:
		bro_uint_t offset;
		offset = c->RequestVal()->AsRecordVal()->Lookup(1)->AsCount();
		reply = nfs3_read_reply(buf, n, nfs_status, offset);
		event = nfs_proc_read;
		break;

	case BifEnum::NFS3::PROC_READLINK:
		reply = nfs3_readlink_reply(buf, n, nfs_status);
		event = nfs_proc_readlink;
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
			reply = new EnumVal(c->Proc(), BifType::Enum::NFS3::proc_t);
			event = nfs_proc_not_implemented;
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
		val_list* vl = event_common_vl(c, rpc_status, nfs_status,
					start_time, last_time, reply_len);

		Val *request = c->TakeRequestVal();

		if ( request )
			vl->append(request);

		if ( reply )
			vl->append(reply);

		analyzer->ConnectionEvent(event, vl);
		}

	Unref(reply);
	return 1;
	}

StringVal* NFS_Interp::nfs3_file_data(const u_char*& buf, int& n, uint64_t offset, int size)
	{
	int data_n;

	// extract the data, move buf and n
	const u_char *data = extract_XDR_opaque(buf, n, data_n, 1 << 30, true);

	// check whether we have to deliver data to the event
	if ( ! BifConst::NFS3::return_data )
		return 0;

	if ( BifConst::NFS3::return_data_first_only && offset != 0 )
		return 0;

	// Ok, so we want to return some data
	data_n = min(data_n, size);
	data_n = min(data_n, int(BifConst::NFS3::return_data_max));

	if ( data_n > 0 )
		return new StringVal(new BroString(data, data_n, 0));

	return 0;
	}

val_list* NFS_Interp::event_common_vl(RPC_CallInfo *c, BifEnum::rpc_status rpc_status,
				      BifEnum::NFS3::status_t nfs_status,
				      double rep_start_time,
				      double rep_last_time, int reply_len)
	{
	// Returns a new val_list that already has a conn_val, and nfs3_info.
	// These are the first parameters for each nfs_* event ...
	val_list *vl = new val_list;
	vl->append(analyzer->BuildConnVal());

	RecordVal *info = new RecordVal(BifType::Record::NFS3::info_t);
	info->Assign(0, new EnumVal(rpc_status, BifType::Enum::rpc_status));
	info->Assign(1, new EnumVal(nfs_status, BifType::Enum::NFS3::status_t));
	info->Assign(2, new Val(c->StartTime(), TYPE_TIME));
	info->Assign(3, new Val(c->LastTime()-c->StartTime(), TYPE_INTERVAL));
	info->Assign(4, new Val(c->RPCLen(), TYPE_COUNT));
	info->Assign(5, new Val(rep_start_time, TYPE_TIME));
	info->Assign(6, new Val(rep_last_time-rep_start_time, TYPE_INTERVAL));
	info->Assign(7, new Val(reply_len, TYPE_COUNT));

	vl->append(info);
	return vl;
	}

StringVal* NFS_Interp::nfs3_fh(const u_char*& buf, int& n)
	{
	int fh_n;
	const u_char* fh = extract_XDR_opaque(buf, n, fh_n, 64);

	if ( ! fh )
		return 0;

	return new StringVal(new BroString(fh, fh_n, 0));
	}

RecordVal* NFS_Interp::nfs3_fattr(const u_char*& buf, int& n)
	{
	RecordVal* attrs = new RecordVal(BifType::Record::NFS3::fattr_t);

	attrs->Assign(0, nfs3_ftype(buf, n));	// file type
	attrs->Assign(1, ExtractUint32(buf, n));	// mode
	attrs->Assign(2, ExtractUint32(buf, n));	// nlink
	attrs->Assign(3, ExtractUint32(buf, n));	// uid
	attrs->Assign(4, ExtractUint32(buf, n));	// gid
	attrs->Assign(5, ExtractUint64(buf, n));	// size
	attrs->Assign(6, ExtractUint64(buf, n));	// used
	attrs->Assign(7, ExtractUint32(buf, n));	// rdev1
	attrs->Assign(8, ExtractUint32(buf, n));	// rdev2
	attrs->Assign(9, ExtractUint64(buf, n));	// fsid
	attrs->Assign(10, ExtractUint64(buf, n));	// fileid
	attrs->Assign(11, ExtractTime(buf, n));	// atime
	attrs->Assign(12, ExtractTime(buf, n));	// mtime
	attrs->Assign(13, ExtractTime(buf, n));	// ctime

	return attrs;
	}

EnumVal* NFS_Interp::nfs3_ftype(const u_char*& buf, int& n)
	{
	BifEnum::NFS3::file_type_t t = (BifEnum::NFS3::file_type_t)extract_XDR_uint32(buf, n);
	return new EnumVal(t, BifType::Enum::NFS3::file_type_t);
	}

RecordVal* NFS_Interp::nfs3_wcc_attr(const u_char*& buf, int& n)
	{
	RecordVal* attrs = new RecordVal(BifType::Record::NFS3::wcc_attr_t);

	attrs->Assign(0, ExtractUint64(buf, n));	// size
	attrs->Assign(1, ExtractTime(buf, n));	// mtime
	attrs->Assign(2, ExtractTime(buf, n));	// ctime

	return attrs;
	}

StringVal *NFS_Interp::nfs3_filename(const u_char*& buf, int& n)
	{
	int name_len;
	const u_char* name = extract_XDR_opaque(buf, n, name_len);

	if ( ! name )
		return 0;

	return new StringVal(new BroString(name, name_len, 0));
	}

RecordVal *NFS_Interp::nfs3_diropargs(const u_char*& buf, int& n)
	{
	RecordVal *diropargs = new RecordVal(BifType::Record::NFS3::diropargs_t);

	diropargs->Assign(0, nfs3_fh(buf, n));
	diropargs->Assign(1, nfs3_filename(buf, n));

	return diropargs;
	}


RecordVal* NFS_Interp::nfs3_post_op_attr(const u_char*& buf, int& n)
	{
	int have_attrs = extract_XDR_uint32(buf, n);

	if ( have_attrs )
		return nfs3_fattr(buf, n);

	return 0;
	}

StringVal* NFS_Interp::nfs3_post_op_fh(const u_char*& buf, int& n)
	{
	int have_fh = extract_XDR_uint32(buf, n);

	if ( have_fh )
		return nfs3_fh(buf, n);

	return 0;
	}

RecordVal* NFS_Interp::nfs3_pre_op_attr(const u_char*& buf, int& n)
	{
	int have_attrs = extract_XDR_uint32(buf, n);

	if ( have_attrs )
		return nfs3_wcc_attr(buf, n);
	return 0;
	}

EnumVal *NFS_Interp::nfs3_stable_how(const u_char*& buf, int& n)
	{
	BifEnum::NFS3::stable_how_t stable = (BifEnum::NFS3::stable_how_t)extract_XDR_uint32(buf, n);
	return new EnumVal(stable, BifType::Enum::NFS3::stable_how_t);
	}

RecordVal* NFS_Interp::nfs3_lookup_reply(const u_char*& buf, int& n, BifEnum::NFS3::status_t status)
	{
	RecordVal *rep = new RecordVal(BifType::Record::NFS3::lookup_reply_t);

	if ( status == BifEnum::NFS3::NFS3ERR_OK )
		{
		rep->Assign(0, nfs3_fh(buf,n));
		rep->Assign(1, nfs3_post_op_attr(buf, n));
		rep->Assign(2, nfs3_post_op_attr(buf, n));
		}
	else
		{
		rep->Assign(0, 0);
		rep->Assign(1, 0);
		rep->Assign(2, nfs3_post_op_attr(buf, n));
		}
	return rep;
	}

RecordVal *NFS_Interp::nfs3_readargs(const u_char*& buf, int& n)
	{
	RecordVal *readargs = new RecordVal(BifType::Record::NFS3::readargs_t);

	readargs->Assign(0, nfs3_fh(buf, n));
	readargs->Assign(1, ExtractUint64(buf, n));  // offset
	readargs->Assign(2, ExtractUint32(buf,n));   // size

	return readargs;
	}

RecordVal* NFS_Interp::nfs3_read_reply(const u_char*& buf, int& n, BifEnum::NFS3::status_t status,
		bro_uint_t offset)
	{
	RecordVal *rep = new RecordVal(BifType::Record::NFS3::read_reply_t);

	if (status == BifEnum::NFS3::NFS3ERR_OK)
		{
		uint32_t bytes_read;

		rep->Assign(0, nfs3_post_op_attr(buf, n));
		bytes_read = extract_XDR_uint32(buf, n);
		rep->Assign(1, new Val(bytes_read, TYPE_COUNT));
		rep->Assign(2, ExtractBool(buf, n));
		rep->Assign(3, nfs3_file_data(buf, n, offset, bytes_read));
		}
	else
		{
		rep->Assign(0, nfs3_post_op_attr(buf, n));
		}

	return rep;
	}

RecordVal* NFS_Interp::nfs3_readlink_reply(const u_char*& buf, int& n, BifEnum::NFS3::status_t status)
	{
	RecordVal *rep = new RecordVal(BifType::Record::NFS3::readlink_reply_t);

	if (status == BifEnum::NFS3::NFS3ERR_OK)
		{
		rep->Assign(0, nfs3_post_op_attr(buf, n));
		rep->Assign(1, nfs3_nfspath(buf,n));
		}
	else
		{
		rep->Assign(0, nfs3_post_op_attr(buf, n));
		}

	return rep;
	}

RecordVal *NFS_Interp::nfs3_writeargs(const u_char*& buf, int& n)
	{
	uint32_t bytes;
	uint64_t offset;
	RecordVal *writeargs = new RecordVal(BifType::Record::NFS3::writeargs_t);

	offset = extract_XDR_uint64(buf, n);
	bytes = extract_XDR_uint32(buf, n);

	writeargs->Assign(0, nfs3_fh(buf, n));
	writeargs->Assign(1, new Val(offset, TYPE_COUNT));
	writeargs->Assign(2, new Val(bytes, TYPE_COUNT));
	writeargs->Assign(3, nfs3_stable_how(buf, n));
	writeargs->Assign(4, nfs3_file_data(buf, n, offset, bytes));

	return writeargs;
	}

RecordVal *NFS_Interp::nfs3_write_reply(const u_char*& buf, int& n, BifEnum::NFS3::status_t status)
	{
	RecordVal *rep = new RecordVal(BifType::Record::NFS3::write_reply_t);

	if ( status == BifEnum::NFS3::NFS3ERR_OK )
		{
		rep->Assign(0, nfs3_pre_op_attr(buf, n));
		rep->Assign(1, nfs3_post_op_attr(buf, n));
		rep->Assign(2, ExtractUint32(buf, n));
		rep->Assign(3, nfs3_stable_how(buf, n));

		// Writeverf. While the RFC says that this should be a fixed
		// length opaque, it specifies the lenght as 8 bytes, so we
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

RecordVal* NFS_Interp::nfs3_newobj_reply(const u_char*& buf, int& n, BifEnum::NFS3::status_t status)
	{
	RecordVal *rep = new RecordVal(BifType::Record::NFS3::newobj_reply_t);

	if (status == BifEnum::NFS3::NFS3ERR_OK)
		{
		int i = 0;
		rep->Assign(0, nfs3_post_op_fh(buf,n));
		rep->Assign(1, nfs3_post_op_attr(buf, n));
		// wcc_data
		rep->Assign(2, nfs3_pre_op_attr(buf, n));
		rep->Assign(3, nfs3_post_op_attr(buf, n));
		}
	else
		{
		rep->Assign(0, 0);
		rep->Assign(1, 0);
		rep->Assign(2, nfs3_pre_op_attr(buf, n));
		rep->Assign(3, nfs3_post_op_attr(buf, n));
		}

	return rep;
	}

RecordVal* NFS_Interp::nfs3_delobj_reply(const u_char*& buf, int& n)
	{
	RecordVal *rep = new RecordVal(BifType::Record::NFS3::delobj_reply_t);

	// wcc_data
	rep->Assign(0, nfs3_pre_op_attr(buf, n));
	rep->Assign(1, nfs3_post_op_attr(buf, n));

	return rep;
	}

RecordVal* NFS_Interp::nfs3_readdirargs(bool isplus, const u_char*& buf, int&n)
	{
	RecordVal *args = new RecordVal(BifType::Record::NFS3::readdirargs_t);

	args->Assign(0, new Val(isplus, TYPE_BOOL));
	args->Assign(1, nfs3_fh(buf, n));
	args->Assign(2, ExtractUint64(buf,n));	// cookie
	args->Assign(3, ExtractUint64(buf,n));	// cookieverf
	args->Assign(4, ExtractUint32(buf,n));	// dircount

	if ( isplus )
		args->Assign(5, ExtractUint32(buf,n));

	return args;
	}

RecordVal* NFS_Interp::nfs3_readdir_reply(bool isplus, const u_char*& buf,
		int&n, BifEnum::NFS3::status_t status)
	{
	RecordVal *rep = new RecordVal(BifType::Record::NFS3::readdir_reply_t);

	rep->Assign(0, new Val(isplus, TYPE_BOOL));

	if ( status == BifEnum::NFS3::NFS3ERR_OK )
		{
		unsigned pos;
		VectorVal *entries = new VectorVal(BifType::Vector::NFS3::direntry_vec_t);

		rep->Assign(1, nfs3_post_op_attr(buf,n));   // dir_attr
		rep->Assign(2, ExtractUint64(buf,n));  // cookieverf

		pos = 1;

		while ( extract_XDR_uint32(buf,n) )
			{
			RecordVal *entry = new RecordVal(BifType::Record::NFS3::direntry_t);
			entry->Assign(0, ExtractUint64(buf,n)); // fileid
			entry->Assign(1, nfs3_filename(buf,n)); // fname
			entry->Assign(2, ExtractUint64(buf,n)); // cookie

			if ( isplus )
				{
				entry->Assign(3, nfs3_post_op_attr(buf,n));
				entry->Assign(4, nfs3_post_op_fh(buf,n));
				}

			entries->Assign(pos, entry);
			pos++;
			}

		rep->Assign(3, entries);
		rep->Assign(4, ExtractBool(buf,n));	// eof
		}
	else
		{
		rep->Assign(1, nfs3_post_op_attr(buf,n));
		}

	return rep;
	}

Val* NFS_Interp::ExtractUint32(const u_char*& buf, int& n)
	{
	return new Val(extract_XDR_uint32(buf, n), TYPE_COUNT);
	}

Val* NFS_Interp::ExtractUint64(const u_char*& buf, int& n)
	{
	return new Val(extract_XDR_uint64(buf, n), TYPE_COUNT);
	}

Val* NFS_Interp::ExtractTime(const u_char*& buf, int& n)
	{
	return new Val(extract_XDR_time(buf, n), TYPE_TIME);
	}

Val* NFS_Interp::ExtractInterval(const u_char*& buf, int& n)
	{
	return new IntervalVal(double(extract_XDR_uint32(buf, n)), 1.0);
	}

Val* NFS_Interp::ExtractBool(const u_char*& buf, int& n)
	{
	return new Val(extract_XDR_uint32(buf, n), TYPE_BOOL);
	}


NFS_Analyzer::NFS_Analyzer(Connection* conn)
	: RPC_Analyzer("RPC", conn, new NFS_Interp(this))
	{
	orig_rpc = resp_rpc = 0;
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
