// $Id: NFS.h 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef nfs_h
#define nfs_h

#include "RPC.h"

class NFS_Interp : public RPC_Interpreter {
public:
	NFS_Interp(Analyzer* arg_analyzer) : RPC_Interpreter(arg_analyzer) { }

protected:
	int RPC_BuildCall(RPC_CallInfo* c, const u_char*& buf, int& n);
	int RPC_BuildReply(const RPC_CallInfo* c, int success,
				const u_char*& buf, int& n,
				EventHandlerPtr& event, Val*& reply);

	StringVal* ExtractFH(const u_char*& buf, int& n);
	RecordVal* ExtractAttrs(const u_char*& buf, int& n);
	RecordVal* ExtractOptAttrs(const u_char*& buf, int& n);
	Val* ExtractCount(const u_char*& buf, int& n);
	Val* ExtractLongAsDouble(const u_char*& buf, int& n);
	Val* ExtractTime(const u_char*& buf, int& n);
	Val* ExtractInterval(const u_char*& buf, int& n);

	void Event(EventHandlerPtr f, Val* request, int status, Val* reply);
};

class NFS_Analyzer : public RPC_Analyzer {
public:
	NFS_Analyzer(Connection* conn);
	virtual void Init();

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new NFS_Analyzer(conn); }

	static bool Available()	{ return nfs_request_getattr || rpc_call; }
};

#endif
