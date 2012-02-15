// See the file "COPYING" in the main distribution directory for copyright.

#ifndef portmap_h
#define portmap_h

#include "RPC.h"

class PortmapperInterp : public RPC_Interpreter {
public:
	PortmapperInterp(Analyzer* arg_analyzer) : RPC_Interpreter(arg_analyzer) { }

protected:
	int RPC_BuildCall(RPC_CallInfo* c, const u_char*& buf, int& n);
	int RPC_BuildReply(RPC_CallInfo* c, BifEnum::rpc_status success,
			   const u_char*& buf, int& n, double start_time,
			   double last_time, int reply_len);
	uint32 CheckPort(uint32 port);

	void Event(EventHandlerPtr f, Val* request, BifEnum::rpc_status status, Val* reply);

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
