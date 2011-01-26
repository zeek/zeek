// $Id: NFS.h 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef nfs_h
#define nfs_h

#include "RPC.h"
#include "XDR.h"
#include "Event.h"

class NFS_Interp : public RPC_Interpreter {
public:
	NFS_Interp(Analyzer* arg_analyzer) : RPC_Interpreter(arg_analyzer) { }

protected:
	int RPC_BuildCall(RPC_CallInfo* c, const u_char*& buf, int& n);
	int RPC_BuildReply(RPC_CallInfo* c, BroEnum::rpc_status rpc_status,
				const u_char*& buf, int& n, double start_time, double last_time,
				int reply_len);

	// returns a new val_list that already has a conn_val, rpc_status and nfs_status.
	// These are the first parameters for each nfs_* event... 
	val_list* event_common_vl(RPC_CallInfo *c, BroEnum::rpc_status rpc_status, 
				BroEnum::nfs3_status nfs_status, double rep_start_time, double rep_last_time,
				int reply_len);

	// These methods parse the appropriate NFSv3 "type" out of buf. If 
	// there are any errors (i.e., buffer to short, etc), buf will be
	// set to 0. However, the methods might still return an allocated
	// Val * !
	// So, you might want to Unref() the Val if buf is 0. 
	// Method names are based on the type names of RFC 1813
	StringVal* nfs3_fh(const u_char*& buf, int& n);
	RecordVal* nfs3_fattr(const u_char*& buf, int& n);
	RecordVal* nfs3_wcc_attr(const u_char*& buf, int& n);
	RecordVal* nfs3_diropargs(const u_char*&buf, int &n);
	StringVal* nfs3_filename(const u_char*& buf, int& n);
	StringVal* nfs3_nfspath(const u_char*& buf, int& n) { return nfs3_filename(buf,n); }
	RecordVal* nfs3_post_op_attr(const u_char*&buf, int &n); // Return 0 or an fattr
	RecordVal* nfs3_pre_op_attr(const u_char*&buf, int &n); // Return 0 or an wcc_attr
	RecordVal* nfs3_lookup_reply(const u_char*& buf, int& n, BroEnum::nfs3_status status);
	RecordVal* nfs3_readargs(const u_char*& buf, int& n);
	RecordVal* nfs3_read_reply(const u_char*& buf, int& n, BroEnum::nfs3_status status);
	RecordVal* nfs3_readlink_reply(const u_char*& buf, int& n, BroEnum::nfs3_status status);
	RecordVal* nfs3_writeargs(const u_char*& buf, int& n);
	EnumVal* nfs3_stable_how(const u_char*& buf, int& n);
	RecordVal* nfs3_write_reply(const u_char*& buf, int& n, BroEnum::nfs3_status status);
	StringVal* nfs3_writeverf(const u_char*& buf, int& n);

	RecordVal* ExtractOptAttrs(const u_char*& buf, int& n);
	Val* ExtractCount(const u_char*& buf, int& n);
	Val* ExtractLongAsDouble(const u_char*& buf, int& n);
	Val* ExtractTime(const u_char*& buf, int& n);
	Val* ExtractInterval(const u_char*& buf, int& n);
	Val* ExtractBool(const u_char*& buf, int& n);
};

class NFS_Analyzer : public RPC_Analyzer {
public:
	NFS_Analyzer(Connection* conn);
	virtual void Init();

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new NFS_Analyzer(conn); }

	//static bool Available()	{ return nfs_request_getattr || rpc_call; }
	static bool Available()	{ return true; }
};

#if 0
namespace nfs3_types {
#define NFS3_MAX_FHSIZE      64
	class nfs3_type {
	public:
		//nfs3_type(const u_char*&buf, int& len) = 0;
		virtual ~nfs3_type()
			 {
			 }
		virtual Val *GetVal() = 0;
		bool IsValid() { return valid; };

		bool valid;
	};

	// A file handle
	class nfs3_fh : public nfs3_type {
	public:
		nfs3_fh(const u_char*&buf, int& len) {
			const u_char *fh_tmp;
			int fh_len;
			valid = false;
			fh_tmp = extract_XDR_opaque(buf,len,fh_len,NFS3_MAX_FHSIZE);
			if (fh_tmp) {
				fh = new StringVal(new BroString(fh, fh_len, 0));
				valid = true;
			}
			else
				fh = 0;
		}

		~nfs3_fh() { printf("~nfs3_fh\n"); }

		Val *GetVal() { return fh; }

		// Data
		StringVal *fh;
	}; // nfs3_fh

};
#endif

#endif
