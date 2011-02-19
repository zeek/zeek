// $Id: NFS.cc 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include "NetVar.h"
#include "XDR.h"
#include "NFS.h"
#include "Event.h"


int NFS_Interp::RPC_BuildCall(RPC_CallInfo* c, const u_char*& buf, int& n)
	{
	if ( c->Program() != 100003 )
		Weird(fmt("bad_RPC_program (%d)", c->Program()));

	uint32 proc = c->Proc();
	// the call arguments, depends on the call type obviously...
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
#if 0
	case BifEnum::NFS3::PROC_LOOKUP:
		{
		StringVal* fh = nfs3_fh(buf, n);

		int name_len;
		const u_char* name = extract_XDR_opaque(buf, n, name_len);

		if ( ! fh || ! name )
			return 0;

		RecordVal* args = new RecordVal(nfs3_lookup_args);
		args->Assign(0, fh);
		args->Assign(1, new StringVal(new BroString(name, name_len, 0)));
		c->AddVal(args);
		}
		break;

	case BifEnum::NFS3::PROC_FSSTAT:
		{
		Val* v = nfs3_fh(buf, n);
		if ( ! v )
			return 0;
		c->AddVal(v);
		}
		break;

	case BifEnum::NFS3::PROC_READ:
		break;
#endif
	default:
		callarg = 0;
		if ( proc < BifEnum::NFS3::PROC_END_OF_PROCS )
			{ // We know the procedure but haven't implemented it
			n = 0; // otherwise DeliverRPC complains about excess_RPC
			}
		else 
			Weird(fmt("unknown_NFS_request(%u)", proc));

		// Return 1 so that replies to unprocessed calls will still
		// be processed, and the return status extracted
		return 1;
	}

	if ( !buf )
		{
		// There was a parse error while trying to extract the call 
		// arguments. However, we don't know where exactly it happened
		// and whether Vals where already allocated (e.g., a RecordVal 
		// was allocated but we failed to fill it). 
		// So we Unref() the call arguments, and we are fine. 
		Unref(callarg);
		callarg = 0;
		return 0;
		}
	c->AddVal(callarg); // it's save to AddVal(0). 

	return 1;
	}

int NFS_Interp::RPC_BuildReply(RPC_CallInfo* c, BifEnum::rpc_status rpc_status,
					const u_char*& buf, int& n, double start_time, double last_time,
					int reply_len)
	{
	EventHandlerPtr event = 0;
	Val *reply = 0;
	BifEnum::NFS3::status_t nfs_status = BifEnum::NFS3::NFS3ERR_OK;
	bool rpc_success = ( rpc_status == BifEnum::RPC_SUCCESS );

	// reply always starts with the NFS status 
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

	switch ( c->Proc() ) {
	case BifEnum::NFS3::PROC_NULL:
		event = nfs_proc_null;
		break;

	case BifEnum::NFS3::PROC_GETATTR:
		if ( rpc_success && nfs_status == BifEnum::NFS3::NFS3ERR_OK )
			reply = nfs3_fattr(buf, n);
		event = nfs_proc_getattr;
		break;

	case BifEnum::NFS3::PROC_LOOKUP:
		if (rpc_success)
			reply = nfs3_lookup_reply(buf, n, nfs_status);
		event = nfs_proc_lookup;
		break;

	case BifEnum::NFS3::PROC_READ:
		if (rpc_success)
			reply = nfs3_read_reply(buf, n, nfs_status);
		event = nfs_proc_read;
		break;

	case BifEnum::NFS3::PROC_READLINK:
		if (rpc_success)
			reply = nfs3_readlink_reply(buf, n, nfs_status);
		event = nfs_proc_readlink;
		break;

	case BifEnum::NFS3::PROC_WRITE:
		if (rpc_success)
			reply = nfs3_write_reply(buf, n, nfs_status);
		event = nfs_proc_write;
		break;

		//if ( nfs_status == BifEnum::NFS3::NFS3ERR_OK )
#if 0
	case BifEnum::NFS3::PROC_LOOKUP:
		if ( success )
			{
			if ( ! buf || status != 0 )
				return 0;

			RecordVal* r = new RecordVal(nfs3_lookup_reply);
			r->Assign(0, nfs3_fh(buf, n));
			r->Assign(1, ExtractOptAttrs(buf, n));
			r->Assign(2, ExtractOptAttrs(buf, n));

			reply = r;
			event = nfs_request_lookup;
			}
		else
			{
			reply = ExtractOptAttrs(buf, n);
			event = nfs_attempt_lookup;
			}

		break;

	case BifEnum::NFS3::PROC_FSSTAT:
		if ( success )
			{
			if ( ! buf || status != 0 )
				return 0;

			RecordVal* r = new RecordVal(nfs3_fsstat);
			r->Assign(0, ExtractOptAttrs(buf, n));
			r->Assign(1, ExtractLongAsDouble(buf, n)); // tbytes
			r->Assign(2, ExtractLongAsDouble(buf, n)); // fbytes
			r->Assign(3, ExtractLongAsDouble(buf, n)); // abytes
			r->Assign(4, ExtractLongAsDouble(buf, n)); // tfiles
			r->Assign(5, ExtractLongAsDouble(buf, n)); // ffiles
			r->Assign(6, ExtractLongAsDouble(buf, n)); // afiles
			r->Assign(7, ExtractInterval(buf, n)); // invarsec

			reply = r;
			event = nfs_request_fsstat;
			}
		else
			{
			reply = ExtractOptAttrs(buf, n);
			event = nfs_attempt_fsstat;
			}

		break;
#endif 

	default:
		if ( c->Proc() < BifEnum::NFS3::PROC_END_OF_PROCS )
			{ // We know the procedure but haven't implemented it
			n = 0; // otherwise DeliverRPC complains about excess_RPC
			reply = new EnumVal(c->Proc(), BifTypePtr::Enum::NFS3::proc_t);
			event = nfs_proc_not_implemented;
			}
		else
			return 0;
	}

	if (!buf)
		{
		// There was a parse error. We have to unref the reply.
		// (see also comments in RPC_BuildCall
		Unref(reply);
		reply = 0;
		return 0;
		}
	// Note: if reply == 0, it won't be added to the val_list for the event.
	// While we can check for that on the policy layer it's kinda ugly, because
	// it's contrary to the event prototype. But having this optional argument to
	// the event is really helpful.... Otherwise I have to let reply
	// point to a RecordVal where all fields are optional and all are set
	// to 0...
	if (event) 
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
	return 1;
	}

val_list* NFS_Interp::event_common_vl(RPC_CallInfo *c, BifEnum::rpc_status rpc_status, 
				BifEnum::NFS3::status_t nfs_status, double rep_start_time, double rep_last_time,
				int reply_len) 
	{
	// returns a new val_list that already has a conn_val, and nfs3_info
	// These are the first parameters for each nfs_* event... 
	val_list *vl = new val_list;
	vl->append(analyzer->BuildConnVal());

	RecordVal *info = new RecordVal(BifTypePtr::Record::NFS3::info_t);
	info->Assign(0, new EnumVal(rpc_status, BifTypePtr::Enum::rpc_status));  
	info->Assign(1, new EnumVal(nfs_status, BifTypePtr::Enum::NFS3::status_t));  
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
	RecordVal* attrs = new RecordVal(BifTypePtr::Record::NFS3::fattr_t);
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
	return new EnumVal(t, BifTypePtr::Enum::NFS3::file_type_t);
	}

RecordVal* NFS_Interp::nfs3_wcc_attr(const u_char*& buf, int& n)
	{
	RecordVal* attrs = new RecordVal(BifTypePtr::Record::NFS3::wcc_attr_t);
	attrs->Assign(0, ExtractUint64(buf, n));	// size
	attrs->Assign(1, ExtractTime(buf, n));	// mtime
	attrs->Assign(2, ExtractTime(buf, n));	// ctime

	return attrs;
	}

StringVal *NFS_Interp::nfs3_filename(const u_char*& buf, int& n) 
	{
	int name_len;
	const u_char* name = extract_XDR_opaque(buf, n, name_len);
	if ( !name )
		return 0;
	return new StringVal(new BroString(name, name_len, 0));
	}

RecordVal *NFS_Interp::nfs3_diropargs(const u_char*& buf, int& n)
	{
	RecordVal *diropargs = new RecordVal(BifTypePtr::Record::NFS3::diropargs_t);
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
	return new EnumVal(stable, BifTypePtr::Enum::NFS3::stable_how_t);
	}

RecordVal* NFS_Interp::nfs3_lookup_reply(const u_char*& buf, int& n, BifEnum::NFS3::status_t status)
	{
	RecordVal *rep = new RecordVal(BifTypePtr::Record::NFS3::lookup_reply_t);
	if (status == BifEnum::NFS3::NFS3ERR_OK)
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
	RecordVal *readargs = new RecordVal(BifTypePtr::Record::NFS3::readargs_t);
	readargs->Assign(0, nfs3_fh(buf, n));
	readargs->Assign(1, ExtractUint64(buf, n));  // offset
	readargs->Assign(2, ExtractUint32(buf,n));   // size 
	return readargs;
	}

RecordVal* NFS_Interp::nfs3_read_reply(const u_char*& buf, int& n, BifEnum::NFS3::status_t status)
	{
	RecordVal *rep = new RecordVal(BifTypePtr::Record::NFS3::read_reply_t);
	if (status == BifEnum::NFS3::NFS3ERR_OK)
		{
		rep->Assign(0, nfs3_post_op_attr(buf, n));
		rep->Assign(1, ExtractUint32(buf, n));
		rep->Assign(2, ExtractBool(buf, n));
		n = 0; // Skip data. TODO: return data to policy layer
		}
	else
		{
		rep->Assign(0, nfs3_post_op_attr(buf, n));
		}
	return rep;
	}

RecordVal* NFS_Interp::nfs3_readlink_reply(const u_char*& buf, int& n, BifEnum::NFS3::status_t status)
	{
	RecordVal *rep = new RecordVal(BifTypePtr::Record::NFS3::readlink_reply_t);
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
	RecordVal *writeargs = new RecordVal(BifTypePtr::Record::NFS3::writeargs_t);
	writeargs->Assign(0, nfs3_fh(buf, n));
	writeargs->Assign(1, ExtractUint64(buf, n));
	writeargs->Assign(2, ExtractUint32(buf,n));
	writeargs->Assign(3, nfs3_stable_how(buf, n));
	n = 0; // Skip data, which is element 4. TODO: pass data to policy layer
	return writeargs;
	}

StringVal* NFS_Interp::nfs3_writeverf(const u_char*& buf, int& n)
	{
	const u_char* verf = extract_XDR_opaque_fixed(buf, n, 8);

	if ( ! verf )
		return 0;

	return new StringVal(new BroString(verf, 8, 0));
	}

RecordVal *NFS_Interp::nfs3_write_reply(const u_char*& buf, int& n, BifEnum::NFS3::status_t status)
	{
	RecordVal *rep = new RecordVal(BifTypePtr::Record::NFS3::write_reply_t);
	if (status == BifEnum::NFS3::NFS3ERR_OK)
		{
		rep->Assign(0, nfs3_pre_op_attr(buf, n));
		rep->Assign(1, nfs3_post_op_attr(buf, n));
		rep->Assign(2, ExtractUint32(buf, n));
		rep->Assign(3, nfs3_stable_how(buf, n));
		rep->Assign(4, nfs3_writeverf(buf, n));
		}
	else
		{
		rep->Assign(0, nfs3_post_op_attr(buf, n));
		rep->Assign(1, nfs3_pre_op_attr(buf, n));
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
: RPC_Analyzer(AnalyzerTag::NFS, conn, new NFS_Interp(this))
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
