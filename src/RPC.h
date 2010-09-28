// $Id: RPC.h 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef rpc_h
#define rpc_h

#include "TCP.h"
#include "UDP.h"

enum {
	RPC_CALL = 0,
	RPC_REPLY = 1,
};

enum {
	RPC_MSG_ACCEPTED = 0,
	RPC_MSG_DENIED = 1,
};

enum {
	RPC_SUCCESS = 0,
	RPC_PROG_UNAVAIL = 1,
	RPC_PROG_MISMATCH = 2,
	RPC_PROC_UNAVAIL = 3,
	RPC_GARBAGE_ARGS = 4,
	RPC_SYSTEM_ERR = 5,
};

enum {
	RPC_MISMATCH = 0,
	RPC_AUTH_ERROR = 1,
};

enum {
	RPC_AUTH_BADCRED = 1,
	RPC_AUTH_REJECTEDCRED = 2,
	RPC_AUTH_BADVERF = 3,
	RPC_AUTH_REJECTEDVERF = 4,
	RPC_AUTH_TOOWEAK = 5,
};

enum {
	RPC_AUTH_NULL = 0,
	RPC_AUTH_UNIX = 1,
	RPC_AUTH_SHORT = 2,
	RPC_AUTH_DES = 3,
};

class RPC_CallInfo {
public:
	RPC_CallInfo(uint32 xid, const u_char*& buf, int& n);
	~RPC_CallInfo();

	void AddVal(Val* arg_v)		{ Unref(v); v = arg_v; }
	Val* RequestVal() const		{ return v; }
	Val* TakeRequestVal()		{ Val* rv = v; v = 0; return rv; }

	int CompareRexmit(const u_char* buf, int n) const;

	uint32 Program() const		{ return prog; }
	uint32 Version() const		{ return vers; }
	uint32 Proc() const		{ return proc; }

	double StartTime() const	{ return start_time; }
	int CallLen() const		{ return call_n; }
	int HeaderLen() const		{ return header_len; }

	uint32 XID() const		{ return xid; }

	void SetValidCall()		{ valid_call = true; }
	bool IsValidCall() const	{ return valid_call; }

protected:
	uint32 xid, rpc_version, prog, vers, proc;
	uint32 cred_flavor, verf_flavor;
	u_char* call_buf;	// copy of original call buffer
	double start_time;
	int call_n;		// size of call buf
	int header_len;		// size of data before the arguments
	bool valid_call;	// whether call was well-formed

	Val* v;		// single (perhaps compound) value corresponding to call
};

declare(PDict,RPC_CallInfo);

class RPC_Interpreter {
public:
	RPC_Interpreter(Analyzer* analyzer);
	virtual ~RPC_Interpreter();

	// Delivers the given RPC.  Returns true if "len" bytes were
	// enough, false otherwise.  "is_orig" is true if the data is
	// from the originator of the connection.
	int DeliverRPC(const u_char* data, int len, int is_orig);

	void Timeout();

protected:
	virtual int RPC_BuildCall(RPC_CallInfo* c, const u_char*& buf, int& n) = 0;
	virtual int RPC_BuildReply(const RPC_CallInfo* c, int success,
					const u_char*& buf, int& n,
					EventHandlerPtr& event, Val*& reply) = 0;

	virtual void Event(EventHandlerPtr f, Val* request, int status, Val* reply) = 0;

	void RPC_Event(RPC_CallInfo* c, int status, int reply_len);

	void Weird(const char* name);

	PDict(RPC_CallInfo) calls;
	Analyzer* analyzer;
};

typedef enum {
	RPC_RECORD_MARKER,	// building up the stream record marker
	RPC_MESSAGE_BUFFER,	// building up the message in the buffer
	RPC_COMPLETE		// message fully built
} TCP_RPC_state;

class Contents_RPC : public TCP_SupportAnalyzer {
public:
	Contents_RPC(Connection* conn, bool orig, RPC_Interpreter* interp);
	virtual ~Contents_RPC();

	TCP_RPC_state State() const		{ return state; }

protected:
	virtual void Init();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(int seq, int len, bool orig);

	virtual void InitBuffer();

	RPC_Interpreter* interp;

	u_char* msg_buf;
	int buf_n;	// number of bytes in msg_buf
	int buf_len;	// size off msg_buf
	int last_frag;	// if this buffer corresponds to the last "fragment"
	bool resync;

	TCP_RPC_state state;
};

class RPC_Analyzer : public TCP_ApplicationAnalyzer {
public:
	RPC_Analyzer(AnalyzerTag::Tag tag, Connection* conn,
			RPC_Interpreter* arg_interp);
	virtual ~RPC_Analyzer();

	virtual void Done();

protected:
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					int seq, const IP_Hdr* ip, int caplen);

	void ExpireTimer(double t);

	RPC_Interpreter* interp;

	Contents_RPC* orig_rpc;
	Contents_RPC* resp_rpc;
};

#include "rpc_pac.h"

class RPC_UDP_Analyzer_binpac : public Analyzer {
public:
	RPC_UDP_Analyzer_binpac(Connection* conn);
	virtual ~RPC_UDP_Analyzer_binpac();

	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					int seq, const IP_Hdr* ip, int caplen);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new RPC_UDP_Analyzer_binpac(conn); }

	static bool Available()
		{ return pm_request || rpc_call; }

protected:
	friend class AnalyzerTimer;
	void ExpireTimer(double t);

	binpac::SunRPC::RPC_Conn* interp;
};

#endif
