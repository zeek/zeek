// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

// A very crude analyzer for NCP (Netware Core Protocol)
//
// For a brief introduction to NCP, take a look at:
//
//	 http://www.protocols.com/pbook/testcss.htm
//
// For list of function codes:
//
//	 http://faydoc.tripod.com/structures/20/2095.htm
//
// And for layout of individual request/reply packets, look at the following
// pages under http://faydoc.tripod.com/structures/, such as:
//
//	http://faydoc.tripod.com/structures/21/2149.htm

#include "zeek/NetVar.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"

#include "analyzer/protocol/ncp/ncp_pac.h"

namespace zeek::analyzer::ncp {
namespace detail {

// Create a general NCP_Session class so that it can be used in
// case the RPC conversation is tunneled through other connections,
// e.g., through an SMB session.

class NCP_Session {
public:
	explicit NCP_Session(analyzer::Analyzer* analyzer);

	void Deliver(bool is_orig, int len, const u_char* data);

	static bool any_ncp_event()
		{
		return ncp_request || ncp_reply;
		}

protected:
	void DeliverFrame(const binpac::NCP::ncp_frame* frame);

	analyzer::Analyzer* analyzer;
	int req_frame_type;
	int req_func;
};

class FrameBuffer {
public:
	explicit FrameBuffer(size_t header_length);
	virtual ~FrameBuffer();

	// Returns -1 if frame is not ready, 0 if it else, and 1 if
	// the frame would require too large of a buffer allocation.
	int Deliver(int& len, const u_char* &data);

	void Reset();

	const u_char* Data() const	{ return msg_buf; }
	int Len() const			{ return msg_len; }
	bool empty() const		{ return buf_n == 0; }

protected:
	virtual void compute_msg_length() = 0;

	size_t hdr_len;
	u_char* msg_buf;
	uint64_t msg_len;
	size_t buf_n;	// number of bytes in msg_buf
	size_t buf_len;	// size off msg_buf
};

#define NCP_TCPIP_HEADER_LENGTH 8

class NCP_FrameBuffer : public FrameBuffer {
public:
	NCP_FrameBuffer() : FrameBuffer(NCP_TCPIP_HEADER_LENGTH) {}

protected:
	void compute_msg_length() override;
};

} // namespace detail

class Contents_NCP_Analyzer : public analyzer::tcp::TCP_SupportAnalyzer {
public:
	Contents_NCP_Analyzer(Connection* conn, bool orig, detail::NCP_Session* session);
	~Contents_NCP_Analyzer() override;

protected:
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;

	detail::NCP_FrameBuffer buffer;
	detail::NCP_Session* session;

	// Re-sync for partial connections (or after a content gap).
	bool resync;
	bool resync_set;
};

class NCP_Analyzer : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
	explicit NCP_Analyzer(Connection* conn);
	~NCP_Analyzer() override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new NCP_Analyzer(conn); }

protected:

	detail::NCP_Session* session;
	Contents_NCP_Analyzer * o_ncp;
	Contents_NCP_Analyzer * r_ncp;
};

} // namespace zeek::analyzer::ncp
