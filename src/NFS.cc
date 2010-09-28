// $Id: NFS.cc 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include "NetVar.h"
#include "XDR.h"
#include "NFS.h"
#include "Event.h"

#define NFS_PROC_NULL 		0
#define NFS_PROC_GETATTR 	1
#define NFS_PROC_SETATTR 	2
#define NFS_PROC_LOOKUP 	3
#define NFS_PROC_READ 		6
#define NFS_PROC_WRITE 		7
#define NFS_PROC_FSSTAT 	18

int NFS_Interp::RPC_BuildCall(RPC_CallInfo* c, const u_char*& buf, int& n)
	{
	if ( c->Program() != 100003 )
		Weird("bad_RPC_program");

	uint32 proc = c->Proc();
	switch ( proc ) {
	case NFS_PROC_NULL:
		break;

	case NFS_PROC_GETATTR:
		{
		Val* v = ExtractFH(buf, n);
		if ( ! v )
			return 0;
		c->AddVal(v);
		}
		break;

	case NFS_PROC_LOOKUP:
		{
		StringVal* fh = ExtractFH(buf, n);

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

	case NFS_PROC_FSSTAT:
		{
		Val* v = ExtractFH(buf, n);
		if ( ! v )
			return 0;
		c->AddVal(v);
		}
		break;

	case NFS_PROC_READ:
		break;

	default:
		Weird(fmt("unknown_NFS_request(%u)", proc));

		// Return 1 so that replies to unprocessed calls will still
		// be processed, and the return status extracted
		return 1;
	}

	return 1;
	}

int NFS_Interp::RPC_BuildReply(const RPC_CallInfo* c, int success,
					const u_char*& buf, int& n,
					EventHandlerPtr& event, Val*& reply)
	{
	reply = 0;
	uint32 status = 0;
	if ( success )
		{
		if ( n >= 4 )
			status = extract_XDR_uint32(buf, n);
		else
			status = 0xffffffff;
		}

	if ( nfs_reply_status )
		{
		val_list* vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(status, TYPE_COUNT));
		analyzer->ConnectionEvent(nfs_reply_status, vl);
		}

	switch ( c->Proc() ) {
	case NFS_PROC_NULL:
		event = success ? nfs_request_null : nfs_attempt_null;
		break;

	case NFS_PROC_GETATTR:
		if ( success )
			{
			if ( ! buf || status != 0 )
				return 0;

			reply = ExtractAttrs(buf, n);
			event = nfs_request_getattr;
			}
		else
			event = nfs_attempt_getattr;

		break;

	case NFS_PROC_LOOKUP:
		if ( success )
			{
			if ( ! buf || status != 0 )
				return 0;

			RecordVal* r = new RecordVal(nfs3_lookup_reply);
			r->Assign(0, ExtractFH(buf, n));
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

	case NFS_PROC_FSSTAT:
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

	default:
		return 0;
	}

	return 1;
	}

StringVal* NFS_Interp::ExtractFH(const u_char*& buf, int& n)
	{
	int fh_n;
	const u_char* fh = extract_XDR_opaque(buf, n, fh_n, 64);

	if ( ! fh )
		return 0;

	return new StringVal(new BroString(fh, fh_n, 0));
	}

RecordVal* NFS_Interp::ExtractAttrs(const u_char*& buf, int& n)
	{
	RecordVal* attrs = new RecordVal(nfs3_attrs);
	attrs->Assign(0, ExtractCount(buf, n));	// file type
	attrs->Assign(1, ExtractCount(buf, n));	// mode
	attrs->Assign(2, ExtractCount(buf, n));	// nlink
	attrs->Assign(3, ExtractCount(buf, n));	// uid
	attrs->Assign(4, ExtractCount(buf, n));	// gid
	attrs->Assign(5, ExtractLongAsDouble(buf, n));	// size
	attrs->Assign(6, ExtractLongAsDouble(buf, n));	// used
	attrs->Assign(7, ExtractCount(buf, n));	// rdev1
	attrs->Assign(8, ExtractCount(buf, n));	// rdev2
	attrs->Assign(9, ExtractLongAsDouble(buf, n));	// fsid
	attrs->Assign(10, ExtractLongAsDouble(buf, n));	// fileid
	attrs->Assign(11, ExtractTime(buf, n));	// atime
	attrs->Assign(12, ExtractTime(buf, n));	// mtime
	attrs->Assign(13, ExtractTime(buf, n));	// ctime

	return attrs;
	}

RecordVal* NFS_Interp::ExtractOptAttrs(const u_char*& buf, int& n)
	{
	int have_attrs = extract_XDR_uint32(buf, n);

	RecordVal* opt_attrs = new RecordVal(nfs3_opt_attrs);
	if ( buf && have_attrs )
		opt_attrs->Assign(0, ExtractAttrs(buf, n));
	else
		opt_attrs->Assign(0, 0);

	return opt_attrs;
	}

Val* NFS_Interp::ExtractCount(const u_char*& buf, int& n)
	{
	return new Val(extract_XDR_uint32(buf, n), TYPE_COUNT);
	}

Val* NFS_Interp::ExtractLongAsDouble(const u_char*& buf, int& n)
	{
	return new Val(extract_XDR_uint64_as_double(buf, n), TYPE_DOUBLE);
	}

Val* NFS_Interp::ExtractTime(const u_char*& buf, int& n)
	{
	return new Val(extract_XDR_time(buf, n), TYPE_TIME);
	}

Val* NFS_Interp::ExtractInterval(const u_char*& buf, int& n)
	{
	return new IntervalVal(double(extract_XDR_uint32(buf, n)), 1.0);
	}

void NFS_Interp::Event(EventHandlerPtr f, Val* request, int status, Val* reply)
	{
	if ( ! f )
		{
		Unref(request);
		Unref(reply);
		return;
		}

	val_list* vl = new val_list;

	vl->append(analyzer->BuildConnVal());
	if ( status == RPC_SUCCESS )
		{
		if ( request )
			vl->append(request);
		if ( reply )
			vl->append(reply);
		}
	else
		{
		vl->append(new Val(status, TYPE_COUNT));
		if ( request )
			vl->append(request);
		}

	analyzer->ConnectionEvent(f, vl);
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
