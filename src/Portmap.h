// $Id: Portmap.h 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef portmap_h
#define portmap_h

#include "RPC.h"

class PortmapperInterp : public RPC_Interpreter {
public:
	PortmapperInterp(Analyzer* arg_analyzer) : RPC_Interpreter(arg_analyzer) { }

protected:
	int RPC_BuildCall(RPC_CallInfo* c, const u_char*& buf, int& n);
	int RPC_BuildReply(const RPC_CallInfo* c, int success,
				const u_char*& buf, int& n,
				EventHandlerPtr& event, Val*& reply);
	uint32 CheckPort(uint32 port);

	void Event(EventHandlerPtr f, Val* request, int status, Val* reply);

	Val* ExtractMapping(const u_char*& buf, int& len);
	Val* ExtractPortRequest(const u_char*& buf, int& len);
	Val* ExtractCallItRequest(const u_char*& buf, int& len);
};

class Portmapper_Analyzer : public RPC_Analyzer {
public:
	Portmapper_Analyzer(Connection* conn);
	virtual ~Portmapper_Analyzer();
	virtual void Init();

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new Portmapper_Analyzer(conn); }

	static bool Available()
		{ return pm_request || rpc_call; }
};

#endif
