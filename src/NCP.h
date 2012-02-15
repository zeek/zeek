// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ncp_h
#define ncp_h

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

#include "NetVar.h"
#include "TCP.h"

#include "ncp_pac.h"

// Create a general NCP_Session class so that it can be used in
// case the RPC conversation is tunneled through other connections,
// e.g., through an SMB session.

class NCP_Session {
public:
	NCP_Session(Analyzer* analyzer);
	virtual ~NCP_Session() {}

	virtual void Deliver(int is_orig, int len, const u_char* data);

	static bool any_ncp_event()
		{
		return ncp_request || ncp_reply;
		}

protected:
	void DeliverFrame(const binpac::NCP::ncp_frame* frame);

	Analyzer* analyzer;
	int req_frame_type;
	int req_func;
};

class FrameBuffer {
public:
	FrameBuffer(int header_length);
	virtual ~FrameBuffer();

	// Returns true if a frame is ready
	bool Deliver(int& len, const u_char* &data);

	void Reset();

	const u_char* Data() const	{ return msg_buf; }
	int Len() const			{ return msg_len; }
	bool empty() const		{ return buf_n == 0; }

protected:
	virtual void compute_msg_length() = 0;

	int hdr_len;
	u_char* msg_buf;
	int msg_len;
	int buf_n;	// number of bytes in msg_buf
	int buf_len;	// size off msg_buf
};

#define NCP_TCPIP_HEADER_LENGTH 8

class NCP_FrameBuffer : public FrameBuffer {
public:
	NCP_FrameBuffer() : FrameBuffer(NCP_TCPIP_HEADER_LENGTH) {}

protected:
	void compute_msg_length();
};

class Contents_NCP_Analyzer : public TCP_SupportAnalyzer {
public:
	Contents_NCP_Analyzer(Connection* conn, bool orig, NCP_Session* session);
	~Contents_NCP_Analyzer();

protected:
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(int seq, int len, bool orig);

	NCP_FrameBuffer buffer;
	NCP_Session* session;

	// Re-sync for partial connections (or after a content gap).
	bool resync;
};

class NCP_Analyzer : public TCP_ApplicationAnalyzer {
public:
	NCP_Analyzer(Connection* conn);
	virtual ~NCP_Analyzer();

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new NCP_Analyzer(conn); }

	static bool Available()	{ return NCP_Session::any_ncp_event(); }

protected:

	NCP_Session* session;
	Contents_NCP_Analyzer * o_ncp;
	Contents_NCP_Analyzer * r_ncp;
};

#endif /* ncp_h */
