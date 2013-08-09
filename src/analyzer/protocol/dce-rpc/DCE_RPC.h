// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_DCE_RPC_DCE_RPC_H
#define ANALYZER_PROTOCOL_DCE_RPC_DCE_RPC_H

// NOTE: This is a somewhat crude analyzer for DCE/RPC (used on Microsoft
// Windows systems) and shouldn't be considered as stable.

#include "NetVar.h"
#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/dce-rpc/events.bif.h"
#include "IPAddr.h"

#include "dce_rpc_simple_pac.h"


namespace analyzer { namespace dce_rpc {

class UUID {
public:
	UUID();
	UUID(const u_char data[16]);
	UUID(const binpac::bytestring &uuid);
	UUID(const char* s);

	const char* to_string() const	{ return s.c_str(); }
	const string& str() const	{ return s; }
	bool operator==(const UUID& u) const
		{ return s == u.str(); }
	bool operator<(const UUID& u) const
		{ return s < u.str(); }

protected:
	u_char data[16];
	string s;
};

const char* uuid_to_string(const u_char* uuid_data);

struct dce_rpc_endpoint_addr {
	// All fields are in host byteorder.
	IPAddr addr;
	u_short port;
	TransportProto proto;

	dce_rpc_endpoint_addr()
		{
		addr = IPAddr();
		port = 0;
		proto = TRANSPORT_UNKNOWN;
		}

	bool is_valid_addr() const
		{ return addr != IPAddr() && port != 0 && proto != TRANSPORT_UNKNOWN; }

	bool operator<(dce_rpc_endpoint_addr const &e) const
		{
		if ( addr != e.addr )
			return addr < e.addr;
		if ( proto != e.proto )
			return proto < e.proto;
		if ( port != e.port )
			return port < e.port;

		return false;
		}

	string to_string() const
		{
		static char buf[128];
		snprintf(buf, sizeof(buf), "%s/%d/%s",
			addr.AsString().c_str(), port,
			proto == TRANSPORT_TCP ? "tcp" :
			(proto == TRANSPORT_UDP ? "udp" : "?"));

		return string(buf);
		}
};

/*
enum DCE_RPC_PTYPE {
	DCE_RPC_REQUEST, DCE_RPC_PING, DCE_RPC_RESPONSE, DCE_RPC_FAULT,
	DCE_RPC_WORKING, DCE_RPC_NOCALL, DCE_RPC_REJECT, DCE_RPC_ACK,
	DCE_RPC_CL_CANCEL, DCE_RPC_FACK, DCE_RPC_CANCEL_ACK, DCE_RPC_BIND,
	DCE_RPC_BIND_ACK, DCE_RPC_BIND_NAK, DCE_RPC_ALTER_CONTEXT,
	DCE_RPC_ALTER_CONTEXT_RESP, DCE_RPC_SHUTDOWN, DCE_RPC_CO_CANCEL,
	DCE_RPC_ORPHANED,
};
*/

#define DCE_RPC_HEADER_LENGTH 16

class DCE_RPC_Header {
public:
	DCE_RPC_Header(analyzer::Analyzer* a, const u_char* bytes);

	BifEnum::dce_rpc_ptype PTYPE() const	{ return ptype; }
	int FragLen() const		{ return frag_len; }
	int LittleEndian() const	{ return bytes[4] >> 4; }
	bool Fragmented() const		{ return fragmented; }

	void Weird(const char* msg)	{ analyzer->Weird(msg); }
	void SetBytes(const u_char* b)	{ bytes = b; }

protected:
	analyzer::Analyzer* analyzer;
	const u_char* bytes;
	BifEnum::dce_rpc_ptype ptype;
	int frag_len;
	bool fragmented;
};

// Create a general DCE_RPC_Session class so that it can be used in
// case the RPC conversation is tunneled through other connections,
// e.g. through an SMB session.

class DCE_RPC_Session {
public:
	DCE_RPC_Session(analyzer::Analyzer* a);
	virtual ~DCE_RPC_Session() {}
	virtual void DeliverPDU(int is_orig, int len, const u_char* data);

	static bool LooksLikeRPC(int len, const u_char* msg);
	static bool any_dce_rpc_event()
		{ return dce_rpc_message || dce_rpc_bind || dce_rpc_request; }

protected:
	void DeliverBind(const binpac::DCE_RPC_Simple::DCE_RPC_PDU* pdu);
	void DeliverRequest(const binpac::DCE_RPC_Simple::DCE_RPC_PDU* pdu);
	void DeliverResponse(const binpac::DCE_RPC_Simple::DCE_RPC_PDU* pdu);

	void DeliverEpmapperRequest(
			const binpac::DCE_RPC_Simple::DCE_RPC_PDU* pdu,
			const binpac::DCE_RPC_Simple::DCE_RPC_Request* req);
	void DeliverEpmapperResponse(
			const binpac::DCE_RPC_Simple::DCE_RPC_PDU* pdu,
			const binpac::DCE_RPC_Simple::DCE_RPC_Response* resp);
	void DeliverEpmapperMapResponse(
			const binpac::DCE_RPC_Simple::DCE_RPC_PDU* pdu,
			const binpac::DCE_RPC_Simple::DCE_RPC_Response* resp);

	analyzer::Analyzer* analyzer;
	UUID if_uuid;
	BifEnum::dce_rpc_if_id if_id;
	int opnum;
	struct {
		dce_rpc_endpoint_addr addr;
		UUID uuid;
	} mapped;
};

class Contents_DCE_RPC_Analyzer : public tcp::TCP_SupportAnalyzer {
public:
	Contents_DCE_RPC_Analyzer(Connection* conn, bool orig, DCE_RPC_Session* session,
		bool speculative);
	~Contents_DCE_RPC_Analyzer();

protected:
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void DeliverPDU(int len, const u_char* data);

	void InitState();

	int speculation;
	u_char* msg_buf;
	int msg_len;
	int buf_n;	// number of bytes in msg_buf
	int buf_len;	// size off msg_buf
	DCE_RPC_Header* hdr;

	bool ParseHeader();

	DCE_RPC_Session* session;
};

class DCE_RPC_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	DCE_RPC_Analyzer(Connection* conn, bool speculative = false);
	~DCE_RPC_Analyzer();

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new DCE_RPC_Analyzer(conn); }

protected:
	DCE_RPC_Session* session;
	bool speculative;
};

} } // namespace analyzer::* 

#endif /* dce_rpc_h */
