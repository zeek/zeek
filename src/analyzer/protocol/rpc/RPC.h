// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "analyzer/protocol/tcp/TCP.h"
#include "NetVar.h"

namespace zeek::analyzer::rpc {
namespace detail {

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
	RPC_CallInfo(uint32_t xid, const u_char*& buf, int& n, double start_time,
		     double last_time, int rpc_len);
	~RPC_CallInfo();

	void AddVal(zeek::ValPtr arg_v)		{ v = std::move(arg_v); }
	const zeek::ValPtr& RequestVal() const		{ return v; }
	zeek::ValPtr TakeRequestVal()		{ auto rv = std::move(v); return rv; }

	bool CompareRexmit(const u_char* buf, int n) const;

	uint32_t Program() const		{ return prog; }
	uint32_t Version() const		{ return vers; }
	uint32_t Proc() const		{ return proc; }
	uint32_t Uid() const { return uid; }
	uint32_t Gid() const { return gid; }
	uint32_t Stamp() const { return stamp; }
	const std::string& MachineName() const { return machinename; }
	const std::vector<int>& AuxGIDs() const { return auxgids; }

	double StartTime() const	{ return start_time; }
	void SetStartTime(double t)	{ start_time = t; }
	double LastTime() const	{ return last_time; }
	void SetLastTime(double t)	{ last_time = t; }
	int CallLen() const		{ return call_n; }
	int RPCLen() const	{ return rpc_len; }
	int HeaderLen() const	{ return header_len; }

	uint32_t XID() const		{ return xid; }

	void SetValidCall()		{ valid_call = true; }
	bool IsValidCall() const	{ return valid_call; }

protected:
	uint32_t xid, rpc_version, prog, vers, proc;
	uint32_t cred_flavor, stamp;
	uint32_t uid, gid;
	std::vector<int> auxgids;
	uint32_t verf_flavor;
	u_char* call_buf;	// copy of original call buffer
	std::string machinename;
	double start_time;
	double last_time;
	int rpc_len;		// size of the full RPC call, incl. xid and msg_type
	int call_n;		// size of call buf
	int header_len;		// size of data before the arguments
	bool valid_call;	// whether call was well-formed

	zeek::ValPtr v;		// single (perhaps compound) value corresponding to call
};

class RPC_Interpreter {
public:
	explicit RPC_Interpreter(zeek::analyzer::Analyzer* analyzer);
	virtual ~RPC_Interpreter();

	// Delivers the given RPC.  Returns true if "len" bytes were
	// enough, false otherwise.  "is_orig" is true if the data is
	// from the originator of the connection.
	int DeliverRPC(const u_char* data, int len, int caplen, bool is_orig, double start_time, double last_time);

	void Timeout();

protected:
	virtual bool RPC_BuildCall(RPC_CallInfo* c, const u_char*& buf, int& n) = 0;
	virtual bool RPC_BuildReply(RPC_CallInfo* c, BifEnum::rpc_status success,
				   const u_char*& buf, int& n, double start_time, double last_time,
				   int reply_len) = 0;

	void Event_RPC_Dialogue(RPC_CallInfo* c, BifEnum::rpc_status status, int reply_len);
	void Event_RPC_Call(RPC_CallInfo* c);
	void Event_RPC_Reply(uint32_t xid, BifEnum::rpc_status status, int reply_len);

	void Weird(const char* name, const char* addl = "");

	std::map<uint32_t, RPC_CallInfo*> calls;
	zeek::analyzer::Analyzer* analyzer;
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
		buf = nullptr;
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

} // namespace detail

/* Support Analyzer for reassembling RPC-over-TCP messages */
class Contents_RPC final : public zeek::analyzer::tcp::TCP_SupportAnalyzer {
public:
	Contents_RPC(zeek::Connection* conn, bool orig, detail::RPC_Interpreter* interp);
	~Contents_RPC() override;

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

	void Init() override;
	virtual bool CheckResync(int& len, const u_char*& data, bool orig);
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;

	virtual void NeedResync() {
		resync_state = NEED_RESYNC;
		resync_toskip = 0;
		state = WAIT_FOR_MESSAGE;
	}

	detail::RPC_Interpreter* interp;

	detail::RPC_Reasm_Buffer marker_buf;	// reassembles the 32bit RPC-over-TCP marker
	detail::RPC_Reasm_Buffer msg_buf;	// reassembles RPC messages
	state_t state;

	double start_time;
	double last_time;

	resync_state_t resync_state;
	int resync_toskip;
};

class RPC_Analyzer : public zeek::analyzer::tcp::TCP_ApplicationAnalyzer {
public:
	RPC_Analyzer(const char* name, zeek::Connection* conn,
	             detail::RPC_Interpreter* arg_interp);
	~RPC_Analyzer() override;

	void Done() override;

protected:
	void DeliverPacket(int len, const u_char* data, bool orig,
					uint64_t seq, const zeek::IP_Hdr* ip, int caplen) override;

	void ExpireTimer(double t);

	detail::RPC_Interpreter* interp;

	Contents_RPC* orig_rpc;
	Contents_RPC* resp_rpc;
};

} // namespace zeek::analyzer::rpc

namespace analyzer::rpc {

constexpr auto RPC_CALL [[deprecated("Remove in v4.1. Uze zeek::analyzer::rpc::detail::RPC_CALL.")]] = zeek::analyzer::rpc::detail::RPC_CALL;
constexpr auto RPC_REPLY [[deprecated("Remove in v4.1. Uze zeek::analyzer::rpc::detail::RPC_REPLY.")]] = zeek::analyzer::rpc::detail::RPC_REPLY;
constexpr auto RPC_MSG_ACCEPTED [[deprecated("Remove in v4.1. Uze zeek::analyzer::rpc::detail::RPC_MSG_ACCEPTED.")]] = zeek::analyzer::rpc::detail::RPC_MSG_ACCEPTED;
constexpr auto RPC_MSG_DENIED [[deprecated("Remove in v4.1. Uze zeek::analyzer::rpc::detail::RPC_MSG_DENIED.")]] = zeek::analyzer::rpc::detail::RPC_MSG_DENIED;
constexpr auto RPC_SUCCESS [[deprecated("Remove in v4.1. Uze zeek::analyzer::rpc::detail::RPC_SUCCESS.")]] = zeek::analyzer::rpc::detail::RPC_SUCCESS;
constexpr auto RPC_PROG_UNAVAIL [[deprecated("Remove in v4.1. Uze zeek::analyzer::rpc::detail::RPC_PROG_UNAVAIL.")]] = zeek::analyzer::rpc::detail::RPC_PROG_UNAVAIL;
constexpr auto RPC_PROG_MISMATCH [[deprecated("Remove in v4.1. Uze zeek::analyzer::rpc::detail::RPC_PROG_MISMATCH.")]] = zeek::analyzer::rpc::detail::RPC_PROG_MISMATCH;
constexpr auto RPC_PROC_UNAVAIL [[deprecated("Remove in v4.1. Uze zeek::analyzer::rpc::detail::RPC_PROC_UNAVAIL.")]] = zeek::analyzer::rpc::detail::RPC_PROC_UNAVAIL;
constexpr auto RPC_GARBAGE_ARGS [[deprecated("Remove in v4.1. Uze zeek::analyzer::rpc::detail::RPC_GARBAGE_ARGS.")]] = zeek::analyzer::rpc::detail::RPC_GARBAGE_ARGS;
constexpr auto RPC_SYSTEM_ERR [[deprecated("Remove in v4.1. Uze zeek::analyzer::rpc::detail::RPC_SYSTEM_ERR.")]] = zeek::analyzer::rpc::detail::RPC_SYSTEM_ERR;
constexpr auto RPC_MISMATCH [[deprecated("Remove in v4.1. Uze zeek::analyzer::rpc::detail::RPC_MISMATCH.")]] = zeek::analyzer::rpc::detail::RPC_MISMATCH;
constexpr auto RPC_AUTH_ERROR [[deprecated("Remove in v4.1. Uze zeek::analyzer::rpc::detail::RPC_AUTH_ERROR.")]] = zeek::analyzer::rpc::detail::RPC_AUTH_ERROR;
constexpr auto RPC_AUTH_BADCRED [[deprecated("Remove in v4.1. Uze zeek::analyzer::rpc::detail::RPC_AUTH_BADCRED.")]] = zeek::analyzer::rpc::detail::RPC_AUTH_BADCRED;
constexpr auto RPC_AUTH_REJECTEDCRED [[deprecated("Remove in v4.1. Uze zeek::analyzer::rpc::detail::RPC_AUTH_REJECTEDCRED.")]] = zeek::analyzer::rpc::detail::RPC_AUTH_REJECTEDCRED;
constexpr auto RPC_AUTH_BADVERF [[deprecated("Remove in v4.1. Uze zeek::analyzer::rpc::detail::RPC_AUTH_BADVERF.")]] = zeek::analyzer::rpc::detail::RPC_AUTH_BADVERF;
constexpr auto RPC_AUTH_REJECTEDVERF [[deprecated("Remove in v4.1. Uze zeek::analyzer::rpc::detail::RPC_AUTH_REJECTEDVERF.")]] = zeek::analyzer::rpc::detail::RPC_AUTH_REJECTEDVERF;
constexpr auto RPC_AUTH_TOOWEAK [[deprecated("Remove in v4.1. Uze zeek::analyzer::rpc::detail::RPC_AUTH_TOOWEAK.")]] = zeek::analyzer::rpc::detail::RPC_AUTH_TOOWEAK;
constexpr auto RPC_AUTH_NULL [[deprecated("Remove in v4.1. Uze zeek::analyzer::rpc::detail::RPC_AUTH_NULL.")]] = zeek::analyzer::rpc::detail::RPC_AUTH_NULL;
constexpr auto RPC_AUTH_UNIX [[deprecated("Remove in v4.1. Uze zeek::analyzer::rpc::detail::RPC_AUTH_UNIX.")]] = zeek::analyzer::rpc::detail::RPC_AUTH_UNIX;
constexpr auto RPC_AUTH_SHORT [[deprecated("Remove in v4.1. Uze zeek::analyzer::rpc::detail::RPC_AUTH_SHORT.")]] = zeek::analyzer::rpc::detail::RPC_AUTH_SHORT;
constexpr auto RPC_AUTH_DES [[deprecated("Remove in v4.1. Uze zeek::analyzer::rpc::detail::RPC_AUTH_DES.")]] = zeek::analyzer::rpc::detail::RPC_AUTH_DES;

using RPC_CallInfo [[deprecated("Remove in v4.1. Use zeek::analyzer::rpc::detail::RPC_CallInfo.")]] = zeek::analyzer::rpc::detail::RPC_CallInfo;
using RPC_Interpreter [[deprecated("Remove in v4.1. Use zeek::analyzer::rpc::detail::RPC_Interpreter.")]] = zeek::analyzer::rpc::detail::RPC_Interpreter;
using RPC_Reasm_Buffer [[deprecated("Remove in v4.1. Use zeek::analyzer::rpc::detail::RPC_Reasm_Buffer.")]] = zeek::analyzer::rpc::detail::RPC_Reasm_Buffer;
using Contents_RPC [[deprecated("Remove in v4.1. Use zeek::analyzer::rpc::Contents_RPC.")]] = zeek::analyzer::rpc::Contents_RPC;
using RPC_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::rpc::RPC_Analyzer.")]] = zeek::analyzer::rpc::RPC_Analyzer;

} // namespace analyzer::rpc
