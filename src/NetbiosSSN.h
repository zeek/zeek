// $Id: NetbiosSSN.h 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef netbios_ssn_h
#define netbios_ssn_h

#include "UDP.h"
#include "TCP.h"
#include "SMB.h"

typedef enum {
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
} NetbiosSSN_Opcode;

//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      TYPE     |     FLAGS     |            LENGTH             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

struct NetbiosSSN_RawMsgHdr {
	NetbiosSSN_RawMsgHdr(const u_char*& data, int& len);

	unsigned int type:8;
	unsigned int flags:8;
	unsigned int length:16;
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

	unsigned int type:8;
	unsigned int flags:8;
	unsigned int id:16;
	unsigned int srcip:32;
	unsigned int srcport:16;
	unsigned int length:16;
	unsigned int offset:16;
};


class NetbiosSSN_Interpreter {
public:
	NetbiosSSN_Interpreter(Analyzer* analyzer, SMB_Session* smb_session);

	int ParseMessage(unsigned int type, unsigned int flags,
			const u_char* data, int len, int is_query);

	// Version used when data points to type/flags/length.
	int ParseMessageTCP(const u_char* data, int len, int is_query);
	int ParseMessageUDP(const u_char* data, int len, int is_query);

	void Timeout()	{ }

	static bool any_netbios_ssn_event()
		{
		return netbios_session_message ||
			netbios_session_request ||
			netbios_session_accepted ||
			netbios_session_rejected ||
			netbios_session_raw_message ||
			netbios_session_ret_arg_resp ||
			netbios_session_keepalive;
		}

protected:
	int ParseSessionMsg(const u_char* data, int len, int is_query);
	int ParseSessionReq(const u_char* data, int len, int is_query);
	int ParseSessionPosResp(const u_char* data, int len, int is_query);
	int ParseSessionNegResp(const u_char* data, int len, int is_query);
	int ParseRetArgResp(const u_char* data, int len, int is_query);
	int ParseKeepAlive(const u_char* data, int len, int is_query);

	// Datagram parsing
	int ParseBroadcast(const u_char* data, int len, int is_query);
	int ParseDatagram(const u_char* data, int len, int is_query);

	int ParseSambaMsg(const u_char* data, int len, int is_query);

	void Event(EventHandlerPtr event, const u_char* data, int len,
			int is_orig = -1);

	// Pass in name/length, returns in xname/xlen the converted
	// name/length.  Returns 0 on failure; xname may still be
	// allocated and hold partial results at that point.
	int ConvertName(const u_char* name, int name_len,
			u_char*& xname, int& xlen);

protected:
	Analyzer* analyzer;
	SMB_Session* smb_session;
};


typedef enum {
	NETBIOS_SSN_TYPE,	// looking for type field
	NETBIOS_SSN_FLAGS,	// looking for flag field
	NETBIOS_SSN_LEN_HI,	// looking for high-order byte of length
	NETBIOS_SSN_LEN_LO,	// looking for low-order byte of length
	NETBIOS_SSN_BUF,	// building up the message in the buffer
} NetbiosSSN_State;

// ### This should be merged with TCP_Contents_RPC, TCP_Contents_DNS.
class Contents_NetbiosSSN : public TCP_SupportAnalyzer {
public:
	Contents_NetbiosSSN(Connection* conn, bool orig,
				NetbiosSSN_Interpreter* interp);
	~Contents_NetbiosSSN();

	void Flush();	// process any partially-received data

	NetbiosSSN_State State() const		{ return state; }

protected:
	virtual void DeliverStream(int len, const u_char* data, bool orig);

	NetbiosSSN_Interpreter* interp;

	unsigned int type;
	unsigned int flags;

	u_char* msg_buf;
	int buf_n;	// number of bytes in msg_buf
	int buf_len;	// size of msg_buf
	int msg_size;	// expected size of message

	NetbiosSSN_State state;
};

class NetbiosSSN_Analyzer : public TCP_ApplicationAnalyzer {
public:
	NetbiosSSN_Analyzer(Connection* conn);
	~NetbiosSSN_Analyzer();

	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					int seq, const IP_Hdr* ip, int caplen);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new NetbiosSSN_Analyzer(conn); }

	static bool Available()
		{
		return NetbiosSSN_Interpreter::any_netbios_ssn_event() ||
			SMB_Session::any_smb_event() ||
			DCE_RPC_Session::any_dce_rpc_event();
		}

protected:
	virtual void ConnectionClosed(TCP_Endpoint* endpoint,
					TCP_Endpoint* peer, int gen_event);
	virtual void EndpointEOF(bool is_orig);

	void ExpireTimer(double t);

	NetbiosSSN_Interpreter* interp;
	SMB_Session* smb_session;
	Contents_NetbiosSSN* orig_netbios;
	Contents_NetbiosSSN* resp_netbios;
	int did_session_done;
};

// FIXME: Doesn't really fit into new analyzer structure. What to do?
int IsReuse(double t, const u_char* pkt);

#endif
