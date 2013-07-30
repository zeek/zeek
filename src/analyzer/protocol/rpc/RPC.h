// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_RPC_RPC_H
#define ANALYZER_PROTOCOL_RPC_RPC_H

#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/udp/UDP.h"

namespace analyzer { namespace rpc {

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
	RPC_CallInfo(uint32 xid, const u_char*& buf, int& n, double start_time,
		     double last_time, int rpc_len);
	~RPC_CallInfo();

	void AddVal(Val* arg_v)		{ Unref(v); v = arg_v; }
	Val* RequestVal() const		{ return v; }
	Val* TakeRequestVal()		{ Val* rv = v; v = 0; return rv; }

	int CompareRexmit(const u_char* buf, int n) const;

	uint32 Program() const		{ return prog; }
	uint32 Version() const		{ return vers; }
	uint32 Proc() const		{ return proc; }

	double StartTime() const	{ return start_time; }
	void SetStartTime(double t)	{ start_time = t; }
	double LastTime() const	{ return last_time; }
	void SetLastTime(double t)	{ last_time = t; }
	int CallLen() const		{ return call_n; }
	int RPCLen() const	{ return rpc_len; }
	int HeaderLen() const	{ return header_len; }

	uint32 XID() const		{ return xid; }

	void SetValidCall()		{ valid_call = true; }
	bool IsValidCall() const	{ return valid_call; }

protected:
	uint32 xid, rpc_version, prog, vers, proc;
	uint32 cred_flavor, verf_flavor;
	u_char* call_buf;	// copy of original call buffer
	double start_time;
	double last_time;
	int rpc_len;		// size of the full RPC call, incl. xid and msg_type
	int call_n;		// size of call buf
	int header_len;		// size of data before the arguments
	bool valid_call;	// whether call was well-formed

	Val* v;		// single (perhaps compound) value corresponding to call
};

declare(PDict,RPC_CallInfo);

class RPC_Interpreter {
public:
	RPC_Interpreter(analyzer::Analyzer* analyzer);
	virtual ~RPC_Interpreter();

	// Delivers the given RPC.  Returns true if "len" bytes were
	// enough, false otherwise.  "is_orig" is true if the data is
	// from the originator of the connection.
	int DeliverRPC(const u_char* data, int len, int caplen, int is_orig, double start_time, double last_time);

	void Timeout();

protected:
	virtual int RPC_BuildCall(RPC_CallInfo* c, const u_char*& buf, int& n) = 0;
	virtual int RPC_BuildReply(RPC_CallInfo* c, BifEnum::rpc_status success,
				   const u_char*& buf, int& n, double start_time, double last_time,
				   int reply_len) = 0;

	void Event_RPC_Dialogue(RPC_CallInfo* c, BifEnum::rpc_status status, int reply_len);
	void Event_RPC_Call(RPC_CallInfo* c);
	void Event_RPC_Reply(uint32_t xid, BifEnum::rpc_status status, int reply_len);

	void Weird(const char* name);

	PDict(RPC_CallInfo) calls;
	analyzer::Analyzer* analyzer;
};


/* A simple buffer for reassembling the fragments that RPC-over-TCP
 * uses. Only needed by RPC_Contents.

 * However, RPC messages can be quite large. As a first step, we only
 * extract and analyzer the first part of an RPC message and skip
 * over the rest.
 *
 * We specify:
 *    maxsize:  the number of bytes we want to copy into the buffer to analyze.
 *    expected: the total number of bytes in the RPC message. Can be
 *              quite large. We will be "skipping over" expected-maxsize bytes.
 *
 * We can extend "expected" (by calling AddToExpected()), but maxsize is
 * fixed.
 *
 * TODO: grow buffer dynamically
 */
class RPC_Reasm_Buffer {
public:
	RPC_Reasm_Buffer() {
		maxsize = expected = 0;
		fill = processed = 0;
		buf = 0;
	};

	~RPC_Reasm_Buffer() { if (buf) delete [] buf; }

	void Init(int64_t arg_maxsize, int64_t arg_expected);

	const u_char *GetBuf() { return buf; }	// Pointer to the buffer
	int64_t GetFill() { return fill; }	// Number of bytes in buf
	int64_t GetSkipped() { return processed-fill; }	// How many bytes did we skipped?
	int64_t GetExpected() { return expected; }	// How many bytes are we expecting?
	int64_t GetProcessed() { return processed; }	// How many bytes are we expecting?

	// Expand expected by delta bytes. Returns false if the number of
	// expected bytes exceeds maxsize (which means that we will truncate
	// the message).
	bool AddToExpected(int64_t delta)
		{ expected += delta; return ! (expected > maxsize); }

	// Consume a chunk of input data (pointed to by data, up len in
	// size). data and len will be adjusted accordingly. Returns true if
	// "expected" bytes have been processed, i.e., returns true when we
	// don't expect any more data.
	bool ConsumeChunk(const u_char*& data, int& len);

protected:
	int64_t fill;	// how many bytes we currently have in the buffer
	int64_t maxsize;	// maximum buffer size we want to allocate
	int64_t processed;	// number of bytes we have processed so far
	int64_t expected;	// number of input bytes we expect
	u_char *buf;

};

/* Support Analyzer for reassembling RPC-over-TCP messages */
class Contents_RPC : public tcp::TCP_SupportAnalyzer {
public:
	Contents_RPC(Connection* conn, bool orig, RPC_Interpreter* interp);
	virtual ~Contents_RPC();

protected:
	typedef enum {
		WAIT_FOR_MESSAGE,
		WAIT_FOR_MARKER,
		WAIT_FOR_DATA,
		WAIT_FOR_LAST_DATA,
	} state_t;

	typedef enum {
		NEED_RESYNC,
		RESYNC_WAIT_FOR_MSG_START,
		RESYNC_WAIT_FOR_FULL_MSG,
		RESYNC_HAD_FULL_MSG,
		INSYNC,
		RESYNC_INIT,
	} resync_state_t;

	virtual void Init();
	virtual bool CheckResync(int& len, const u_char*& data, bool orig);
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(int seq, int len, bool orig);

	virtual void NeedResync() {
		resync_state = NEED_RESYNC;
		resync_toskip = 0;
		state = WAIT_FOR_MESSAGE;
	}

	RPC_Interpreter* interp;

	RPC_Reasm_Buffer marker_buf;	// reassembles the 32bit RPC-over-TCP marker
	RPC_Reasm_Buffer msg_buf;	// reassembles RPC messages
	state_t state;

	double start_time;
	double last_time;

	resync_state_t resync_state;
	int resync_toskip;
};

class RPC_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	RPC_Analyzer(const char* name, Connection* conn,
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

} } // namespace analyzer::* 

#endif
