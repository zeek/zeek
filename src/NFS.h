// $Id: NFS.h 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef nfs_h
#define nfs_h

#include "RPC.h"
#include "XDR.h"

class NFS_Interp : public RPC_Interpreter {
public:
	NFS_Interp(Analyzer* arg_analyzer) : RPC_Interpreter(arg_analyzer) { }

protected:
	int RPC_BuildCall(RPC_CallInfo* c, const u_char*& buf, int& n);
	int RPC_BuildReply(RPC_CallInfo* c, BroEnum::rpc_status success,
				const u_char*& buf, int& n);

	StringVal* ExtractFH(const u_char*& buf, int& n);
	RecordVal* ExtractAttrs(const u_char*& buf, int& n);
	RecordVal* ExtractOptAttrs(const u_char*& buf, int& n);
	Val* ExtractCount(const u_char*& buf, int& n);
	Val* ExtractLongAsDouble(const u_char*& buf, int& n);
	Val* ExtractTime(const u_char*& buf, int& n);
	Val* ExtractInterval(const u_char*& buf, int& n);

	void Event(EventHandlerPtr f, Val* request, BroEnum::rpc_status status, Val* reply);
};

class NFS_Analyzer : public RPC_Analyzer {
public:
	NFS_Analyzer(Connection* conn);
	virtual void Init();

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new NFS_Analyzer(conn); }

	//static bool Available()	{ return nfs_request_getattr || rpc_call; }
	static bool Available()	{ return nfs_request_null || rpc_call; }
};

namespace nfs3_types {
#define NFS3_MAX_FHSIZE      64
	class nfs3_type : public RPC_CallInfo_Cookie {
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
				fh.Set(fh_tmp, fh_len, 0);
				valid = true;
			}
			else
				fh = 0;
		}

		~nfs3_fh() { printf("~nfs3_fh\n"); }

		Val *GetVal() { return new StringVal(new BroString(fh)); }

		// Data
		BroString fh;
	}; // nfs3_fh

};

#endif
