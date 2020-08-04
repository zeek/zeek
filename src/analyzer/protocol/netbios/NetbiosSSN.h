// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "analyzer/protocol/udp/UDP.h"
#include "analyzer/protocol/tcp/TCP.h"

namespace zeek::analyzer::netbios_ssn {
namespace detail {

enum NetbiosSSN_Opcode {
	NETBIOS_SSN_MSG = 0x0,
	NETBIOS_DGM_DIRECT_UNIQUE = 0x10,
	NETBIOS_DGM_DIRECT_GROUP = 0x11,
	NETBIOS_DGM_BROADCAST = 0x12,
	NETBIOS_DGM_ERROR = 0x13,
	NETBIOS_DGG_QUERY_REQ = 0x14,
	NETBIOS_DGM_POS_RESP = 0x15,
	NETBIOS_DGM_NEG_RESP = 0x16,
	NETBIOS_SSN_REQ = 0x81,
	NETBIOS_SSN_POS_RESP = 0x82,
	NETBIOS_SSN_NEG_RESP = 0x83,
	NETBIOS_SSN_RETARG_RESP = 0x84,
	NETBIOS_SSN_KEEP_ALIVE = 0x85,
};

//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      TYPE     |     FLAGS     |            LENGTH             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

struct NetbiosSSN_RawMsgHdr {
	NetbiosSSN_RawMsgHdr(const u_char*& data, int& len);

	uint8_t type;
	uint8_t flags;
	uint16_t length;
};

//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   MSG_TYPE    |     FLAGS     |           DGM_ID              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           SOURCE_IP                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          SOURCE_PORT          |          DGM_LENGTH           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         PACKET_OFFSET         |                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |

struct NetbiosDGM_RawMsgHdr {
	NetbiosDGM_RawMsgHdr(const u_char*& data, int& len);

	uint8_t type;
	uint8_t flags;
	uint16_t id;
	uint32_t srcip;
	uint16_t srcport;
	uint16_t length;
	uint16_t offset;
};

enum NetbiosSSN_State {
	NETBIOS_SSN_TYPE,	// looking for type field
	NETBIOS_SSN_FLAGS,	// looking for flag field
	NETBIOS_SSN_LEN_HI,	// looking for high-order byte of length
	NETBIOS_SSN_LEN_LO,	// looking for low-order byte of length
	NETBIOS_SSN_BUF,	// building up the message in the buffer
};

class NetbiosSSN_Interpreter {
public:
	explicit NetbiosSSN_Interpreter(zeek::analyzer::Analyzer* analyzer);

	void ParseMessage(unsigned int type, unsigned int flags,
			const u_char* data, int len, bool is_query);

	// Version used when data points to type/flags/length.
	void ParseMessageTCP(const u_char* data, int len, bool is_query);
	void ParseMessageUDP(const u_char* data, int len, bool is_query);

	void Timeout()	{ }

protected:
	void ParseSessionMsg(const u_char* data, int len, bool is_query);
	void ParseSessionReq(const u_char* data, int len, bool is_query);
	void ParseSessionPosResp(const u_char* data, int len, bool is_query);
	void ParseSessionNegResp(const u_char* data, int len, bool is_query);
	void ParseRetArgResp(const u_char* data, int len, bool is_query);
	void ParseKeepAlive(const u_char* data, int len, bool is_query);

	// Datagram parsing
	void ParseBroadcast(const u_char* data, int len, bool is_query);
	void ParseDatagram(const u_char* data, int len, bool is_query);

	void ParseSambaMsg(const u_char* data, int len, bool is_query);

	void Event(zeek::EventHandlerPtr event, const u_char* data, int len,
	           int is_orig = -1);

	// Pass in name/length, returns in xname/xlen the converted
	// name/length.  Returns 0 on failure; xname may still be
	// allocated and hold partial results at that point.
	int ConvertName(const u_char* name, int name_len,
			u_char*& xname, int& xlen);

protected:
	zeek::analyzer::Analyzer* analyzer;
	//SMB_Session* smb_session;
};

} // namespace detail

// ### This should be merged with TCP_Contents_RPC, TCP_Contents_DNS.
class Contents_NetbiosSSN final : public zeek::analyzer::tcp::TCP_SupportAnalyzer {
public:
	Contents_NetbiosSSN(zeek::Connection* conn, bool orig,
	                    detail::NetbiosSSN_Interpreter* interp);
	~Contents_NetbiosSSN() override;

	void Flush();	// process any partially-received data

	detail::NetbiosSSN_State State() const		{ return state; }

protected:
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void ProcessChunk(int& len, const u_char*& data, bool orig);

	detail::NetbiosSSN_Interpreter* interp;

	unsigned int type;
	unsigned int flags;

	u_char* msg_buf;
	int buf_n;	// number of bytes in msg_buf
	int buf_len;	// size of msg_buf
	int msg_size;	// expected size of message

	detail::NetbiosSSN_State state;
};

class NetbiosSSN_Analyzer final : public zeek::analyzer::tcp::TCP_ApplicationAnalyzer {
public:
	explicit NetbiosSSN_Analyzer(zeek::Connection* conn);
	~NetbiosSSN_Analyzer() override;

	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig,
	                   uint64_t seq, const zeek::IP_Hdr* ip, int caplen) override;

	static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn)
		{ return new NetbiosSSN_Analyzer(conn); }

protected:
	void ConnectionClosed(zeek::analyzer::tcp::TCP_Endpoint* endpoint,
	                      zeek::analyzer::tcp::TCP_Endpoint* peer, bool gen_event) override;
	void EndpointEOF(bool is_orig) override;

	void ExpireTimer(double t);

	detail::NetbiosSSN_Interpreter* interp;
	//SMB_Session* smb_session;
	Contents_NetbiosSSN* orig_netbios;
	Contents_NetbiosSSN* resp_netbios;
	int did_session_done;
};

// FIXME: Doesn't really fit into new analyzer structure. What to do?
int IsReuse(double t, const u_char* pkt);

} // namespace zeek::analyzer::netbios_ssn

namespace analyzer::netbios_ssn {

using NetbiosSSN_Opcode [[deprecated("Remove in v4.1. Use zeek::analyzer::netbios_ssn::detail::NetbiosSSN_Opcode.")]] = zeek::analyzer::netbios_ssn::detail::NetbiosSSN_Opcode;
constexpr auto NETBIOS_SSN_MSG [[deprecated("Remove in v4.1. Uze zeek::analyzer::netbios_ssn::detail::NETBIOS_SSN_MSG.")]] = zeek::analyzer::netbios_ssn::detail::NETBIOS_SSN_MSG;
constexpr auto NETBIOS_DGM_DIRECT_UNIQUE [[deprecated("Remove in v4.1. Uze zeek::analyzer::netbios_ssn::detail::NETBIOS_DGM_DIRECT_UNIQUE.")]] = zeek::analyzer::netbios_ssn::detail::NETBIOS_DGM_DIRECT_UNIQUE;
constexpr auto NETBIOS_DGM_DIRECT_GROUP [[deprecated("Remove in v4.1. Uze zeek::analyzer::netbios_ssn::detail::NETBIOS_DGM_DIRECT_GROUP.")]] = zeek::analyzer::netbios_ssn::detail::NETBIOS_DGM_DIRECT_GROUP;
constexpr auto NETBIOS_DGM_BROADCAST [[deprecated("Remove in v4.1. Uze zeek::analyzer::netbios_ssn::detail::NETBIOS_DGM_BROADCAST.")]] = zeek::analyzer::netbios_ssn::detail::NETBIOS_DGM_BROADCAST;
constexpr auto NETBIOS_DGM_ERROR [[deprecated("Remove in v4.1. Uze zeek::analyzer::netbios_ssn::detail::NETBIOS_DGM_ERROR.")]] = zeek::analyzer::netbios_ssn::detail::NETBIOS_DGM_ERROR;
constexpr auto NETBIOS_DGG_QUERY_REQ [[deprecated("Remove in v4.1. Uze zeek::analyzer::netbios_ssn::detail::NETBIOS_DGG_QUERY_REQ.")]] = zeek::analyzer::netbios_ssn::detail::NETBIOS_DGG_QUERY_REQ;
constexpr auto NETBIOS_DGM_POS_RESP [[deprecated("Remove in v4.1. Uze zeek::analyzer::netbios_ssn::detail::NETBIOS_DGM_POS_RESP.")]] = zeek::analyzer::netbios_ssn::detail::NETBIOS_DGM_POS_RESP;
constexpr auto NETBIOS_DGM_NEG_RESP [[deprecated("Remove in v4.1. Uze zeek::analyzer::netbios_ssn::detail::NETBIOS_DGM_NEG_RESP.")]] = zeek::analyzer::netbios_ssn::detail::NETBIOS_DGM_NEG_RESP;
constexpr auto NETBIOS_SSN_REQ [[deprecated("Remove in v4.1. Uze zeek::analyzer::netbios_ssn::detail::NETBIOS_SSN_REQ.")]] = zeek::analyzer::netbios_ssn::detail::NETBIOS_SSN_REQ;
constexpr auto NETBIOS_SSN_POS_RESP [[deprecated("Remove in v4.1. Uze zeek::analyzer::netbios_ssn::detail::NETBIOS_SSN_POS_RESP.")]] = zeek::analyzer::netbios_ssn::detail::NETBIOS_SSN_POS_RESP;
constexpr auto NETBIOS_SSN_NEG_RESP [[deprecated("Remove in v4.1. Uze zeek::analyzer::netbios_ssn::detail::NETBIOS_SSN_NEG_RESP.")]] = zeek::analyzer::netbios_ssn::detail::NETBIOS_SSN_NEG_RESP;
constexpr auto NETBIOS_SSN_RETARG_RESP [[deprecated("Remove in v4.1. Uze zeek::analyzer::netbios_ssn::detail::NETBIOS_SSN_RETARG_RESP.")]] = zeek::analyzer::netbios_ssn::detail::NETBIOS_SSN_RETARG_RESP;
constexpr auto NETBIOS_SSN_KEEP_ALIVE [[deprecated("Remove in v4.1. Uze zeek::analyzer::netbios_ssn::detail::NETBIOS_SSN_KEEP_ALIVE.")]] = zeek::analyzer::netbios_ssn::detail::NETBIOS_SSN_KEEP_ALIVE;

using NetbiosSSN_RawMsgHdr [[deprecated("Remove in v4.1. Use zeek::analyzer::netbios_ssn::detail::NetbiosSSN_RawMsgHdr.")]] = zeek::analyzer::netbios_ssn::detail::NetbiosSSN_RawMsgHdr;
using NetbiosDGM_RawMsgHdr [[deprecated("Remove in v4.1. Use zeek::analyzer::netbios_ssn::detail::NetbiosDGM_RawMsgHdr.")]] = zeek::analyzer::netbios_ssn::detail::NetbiosDGM_RawMsgHdr;

using NetbiosSSN_State [[deprecated("Remove in v4.1. Use zeek::analyzer::netbios_ssn::detail::NetbiosSSN_State.")]] = zeek::analyzer::netbios_ssn::detail::NetbiosSSN_State;
constexpr auto NETBIOS_SSN_TYPE [[deprecated("Remove in v4.1. Uze zeek::analyzer::netbios_ssn::detail::NETBIOS_SSN_TYPE.")]] = zeek::analyzer::netbios_ssn::detail::NETBIOS_SSN_TYPE;
constexpr auto NETBIOS_SSN_FLAGS [[deprecated("Remove in v4.1. Uze zeek::analyzer::netbios_ssn::detail::NETBIOS_SSN_FLAGS.")]] = zeek::analyzer::netbios_ssn::detail::NETBIOS_SSN_FLAGS;
constexpr auto NETBIOS_SSN_LEN_HI [[deprecated("Remove in v4.1. Uze zeek::analyzer::netbios_ssn::detail::NETBIOS_SSN_LEN_HI.")]] = zeek::analyzer::netbios_ssn::detail::NETBIOS_SSN_LEN_HI;
constexpr auto NETBIOS_SSN_LEN_LO [[deprecated("Remove in v4.1. Uze zeek::analyzer::netbios_ssn::detail::NETBIOS_SSN_LEN_LO.")]] = zeek::analyzer::netbios_ssn::detail::NETBIOS_SSN_LEN_LO;
constexpr auto NETBIOS_SSN_BUF [[deprecated("Remove in v4.1. Uze zeek::analyzer::netbios_ssn::detail::NETBIOS_SSN_BUF.")]] = zeek::analyzer::netbios_ssn::detail::NETBIOS_SSN_BUF;

using NetbiosSSN_Interpreter [[deprecated("Remove in v4.1. Use zeek::analyzer::netbios_ssn::detail::NetbiosSSN_Interpreter.")]] = zeek::analyzer::netbios_ssn::detail::NetbiosSSN_Interpreter;
using Contents_NetbiosSSN [[deprecated("Remove in v4.1. Use zeek::analyzer::netbios_ssn::Contents_NetbiosSSN.")]] = zeek::analyzer::netbios_ssn::Contents_NetbiosSSN;
using NetbiosSSN_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::netbios_ssn::NetbiosSSN_Analyzer.")]] = zeek::analyzer::netbios_ssn::NetbiosSSN_Analyzer;

} // namespace analyzer::netbios_ssn
