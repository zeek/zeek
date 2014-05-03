// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_DNS_DNS_H
#define ANALYZER_PROTOCOL_DNS_DNS_H

#include "analyzer/protocol/tcp/TCP.h"
#include "binpac_bro.h"

namespace analyzer { namespace dns {

typedef enum {
	DNS_OP_QUERY = 0,		///< standard query
	DNS_OP_IQUERY = 1,		///< reverse query

	// ### Is server status 2 or 3? RFC 1035 says it's 2
	// DNS_OP_SERVER_STATUS = 3,	///< server status request
	DNS_OP_SERVER_STATUS = 2,	///< server status request

	// Netbios operations (query = 0).
	NETBIOS_REGISTRATION = 5,
	NETBIOS_RELEASE = 6,
	NETBIOS_WACK = 7,		// wait for ACK
	NETBIOS_REFRESH = 8,
} DNS_Opcode;

typedef enum {
	DNS_CODE_OK = 0,		///< no error
	DNS_CODE_FORMAT_ERR = 1,	///< format error
	DNS_CODE_SERVER_FAIL = 2,	///< server failure
	DNS_CODE_NAME_ERR = 3,		///< no such domain
	DNS_CODE_NOT_IMPL = 4,		///< not implemented
	DNS_CODE_REFUSED = 5,		///< refused
} DNS_Code;

typedef enum {
	TYPE_A = 1,		///< host address
	TYPE_NS = 2,		///< authoritative name server
	TYPE_CNAME = 5,		///< canonical name
	TYPE_SOA = 6,		///< start of authority
	TYPE_WKS = 11,		///< well known service
	TYPE_PTR = 12,		///< domain name pointer
	TYPE_HINFO = 13,	///< host information
	TYPE_MX = 15,		///< mail routing information
	TYPE_TXT = 16,		///< text strings
	TYPE_SIG = 24,		///< digital signature (RFC 2535)
	TYPE_KEY = 25,		///< public key (RFC 2535)
	TYPE_PX = 26,		///< pointer to X.400/RFC822 mapping info (RFC 1664)
	TYPE_AAAA = 28,		///< IPv6 address (RFC 1886
	TYPE_NBS = 32,		///< Netbios name (RFC 1002)
	TYPE_SRV = 33,		///< service location (RFC 2052)
	TYPE_NAPTR = 35,	///< naming authority pointer (RFC 2168)
	TYPE_KX = 36,		///< Key Exchange (RFC 2230)
	TYPE_CERT = 37,		///< Certificate (RFC 2538)
	TYPE_A6 = 38,		///< IPv6 address with indirection (RFC 2874)
	TYPE_DNAME = 39,	///< Non-terminal DNS name redirection (RFC 2672)
	TYPE_EDNS = 41,		///< OPT pseudo-RR (RFC 2671)
	TYPE_TKEY = 249,	///< Transaction Key (RFC 2930)
	TYPE_TSIG = 250,	///< Transaction Signature (RFC 2845)

	// The following are only valid in queries.
	TYPE_AXFR = 252,
	TYPE_ALL = 255,
	TYPE_WINS = 65281,	///< Microsoft's WINS RR
	TYPE_WINSR = 65282,	///< Microsoft's WINS-R RR
} RR_Type;

#define DNS_CLASS_IN 1
#define DNS_CLASS_ANY 255

typedef enum {
	DNS_QUESTION,
	DNS_ANSWER,
	DNS_AUTHORITY,
	DNS_ADDITIONAL,
} DNS_AnswerType;


struct DNS_RawMsgHdr {
	unsigned short id;
	unsigned short flags;
	unsigned short qdcount;
	unsigned short ancount;
	unsigned short nscount;
	unsigned short arcount;
};

struct EDNS_ADDITIONAL {		// size
	unsigned short name;		// -
	unsigned short type;		// 16 : ExtractShort(data, len)
	unsigned short payload_size;	// 16
	unsigned short extended_rcode;	// 8
	unsigned short version;		// 8
	unsigned short z;		// 16
	unsigned short rdata_len;	// 16
};

struct TSIG_DATA {
	BroString* alg_name;
	unsigned long time_s;
	unsigned short time_ms;
	BroString* sig;
	unsigned short fudge;
	unsigned short orig_id;
	unsigned short rr_error;
};

class DNS_MsgInfo {
public:
	DNS_MsgInfo(DNS_RawMsgHdr* hdr, int is_query);
	~DNS_MsgInfo();

	Val* BuildHdrVal();
	Val* BuildAnswerVal();
	Val* BuildEDNS_Val();
	Val* BuildTSIG_Val();

	int id;
	int opcode;	///< query type, see DNS_Opcode
	int rcode;	///< return code, see DNS_Code
	int QR;		///< query record flag
	int AA;		///< authoritiave answer flag
	int TC;		///< truncated - size > 512 bytes for udp
	int RD;		///< recursion desired
	int RA;		///< recursion available
	int  Z;		///< zero - this 3 bit field *must* be zero
	int qdcount;	///< number of questions
	int ancount;	///< number of answers
	int nscount;	///< number of authority RRs
	int arcount;	///< number of additional RRs
	int is_query;	///< whether it came from the session initiator

	StringVal* query_name;
	RR_Type atype;
	int aclass;	///< normally = 1, inet
	int ttl;

	DNS_AnswerType answer_type;
	int skip_event;		///< if true, don't generate corresponding events
	// int answer_count;	///< count of responders.  if >1 and not
				///< identical answer, there may be problems
	// uint32* addr;	///< cache value to pass back results
				///< for forward lookups

	// More values for spesific DNS types.
	// struct EDNS_ADDITIONAL* edns;

	struct TSIG_DATA* tsig;
};


class DNS_Interpreter {
public:
	DNS_Interpreter(analyzer::Analyzer* analyzer);

	int ParseMessage(const u_char* data, int len, int is_query);

	void Timeout()	{ }

protected:
	int EndMessage(DNS_MsgInfo* msg);

	int ParseQuestions(DNS_MsgInfo* msg,
				const u_char*& data, int& len,
				const u_char* start);
	int ParseAnswers(DNS_MsgInfo* msg, int n, DNS_AnswerType answer_type,
				const u_char*& data, int& len,
				const u_char* start);

	int ParseQuestion(DNS_MsgInfo* msg,
			const u_char*& data, int& len, const u_char* start);
	int ParseAnswer(DNS_MsgInfo* msg,
			const u_char*& data, int& len, const u_char* start);

	u_char* ExtractName(const u_char*& data, int& len,
				u_char* label, int label_len,
				const u_char* msg_start);
	int ExtractLabel(const u_char*& data, int& len,
			 u_char*& label, int& label_len,
			 const u_char* msg_start);

	uint16 ExtractShort(const u_char*& data, int& len);
	uint32 ExtractLong(const u_char*& data, int& len);

	int ParseRR_Name(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start);
	int ParseRR_SOA(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start);
	int ParseRR_MX(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start);
	int ParseRR_NBS(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start);
	int ParseRR_SRV(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start);
	int ParseRR_EDNS(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start);
	int ParseRR_A(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength);
	int ParseRR_AAAA(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength);
	int ParseRR_WKS(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength);
	int ParseRR_HINFO(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength);
	int ParseRR_TXT(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start);
	int ParseRR_TSIG(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start);

	void SendReplyOrRejectEvent(DNS_MsgInfo* msg, EventHandlerPtr event,
					const u_char*& data, int& len,
					BroString* question_name);

	analyzer::Analyzer* analyzer;
};


typedef enum {
	DNS_LEN_HI,		///< looking for the high-order byte of the length
	DNS_LEN_LO,		///< looking for the low-order byte of the length
	DNS_MESSAGE_BUFFER,	///< building up the message in the buffer
} TCP_DNS_state;

// Support analyzer which chunks the TCP stream into "packets".
// ### This should be merged with TCP_Contents_RPC.
class Contents_DNS : public tcp::TCP_SupportAnalyzer {
public:
	Contents_DNS(Connection* c, bool orig, DNS_Interpreter* interp);
	~Contents_DNS();

	void Flush();		///< process any partially-received data

	TCP_DNS_state State() const	{ return state; }

protected:
	virtual void DeliverStream(int len, const u_char* data, bool orig);

	DNS_Interpreter* interp;

	u_char* msg_buf;
	int buf_n;		///< number of bytes in msg_buf
	int buf_len;		///< size of msg_buf
	int msg_size;		///< expected size of message
	TCP_DNS_state state;
};

// Works for both TCP and UDP.
class DNS_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	DNS_Analyzer(Connection* conn);
	~DNS_Analyzer();

	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					int seq, const IP_Hdr* ip, int caplen);

	virtual void Init();
	virtual void Done();
	virtual void ConnectionClosed(tcp::TCP_Endpoint* endpoint,
					tcp::TCP_Endpoint* peer, int gen_event);

	void ExpireTimer(double t);

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new DNS_Analyzer(conn); }

protected:
	DNS_Interpreter* interp;
	Contents_DNS* contents_dns_orig;
	Contents_DNS* contents_dns_resp;
	int did_session_done;
};

// FIXME: Doesn't really fit into new analyzer structure. What to do?
int IsReuse(double t, const u_char* pkt);

} } // namespace analyzer::* 

#endif
