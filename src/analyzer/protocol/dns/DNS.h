// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "analyzer/protocol/tcp/TCP.h"
#include "binpac_zeek.h"

namespace zeek::analyzer::dns {
namespace detail {

enum DNS_Opcode {
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
};

enum DNS_Code {
	DNS_CODE_OK = 0,		///< no error
	DNS_CODE_FORMAT_ERR = 1,	///< format error
	DNS_CODE_SERVER_FAIL = 2,	///< server failure
	DNS_CODE_NAME_ERR = 3,		///< no such domain
	DNS_CODE_NOT_IMPL = 4,		///< not implemented
	DNS_CODE_REFUSED = 5,		///< refused
};

enum RR_Type {
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
	TYPE_CAA = 257,		///< Certification Authority Authorization (RFC 6844)
	TYPE_SSHFP = 44,	///< SSH Public Key Fingerprint (RFC 4255)
	TYPE_LOC = 29,		///< Location information about hosts (RFC 1876)
	// DNSSEC RR's
	TYPE_RRSIG = 46,	///< RR Signature record type (RFC4043)
	TYPE_NSEC = 47,		///< Next Secure record (RFC4043)
	TYPE_DNSKEY = 48,	///< DNS Key record (RFC 4034)
	TYPE_DS = 43,		///< Delegation signer (RFC 4034)
	TYPE_NSEC3 = 50,
	TYPE_NSEC3PARAM = 51,	///< Contains the NSEC3 parameters (RFC 5155)
	// Obsoleted
	TYPE_SPF = 99,          ///< Alternative: storing SPF data in TXT records, using the same format (RFC 4408). Support for it was discontinued in RFC 7208
	// The following are only valid in queries.
	TYPE_AXFR = 252,
	TYPE_ALL = 255,
	TYPE_WINS = 65281,	///< Microsoft's WINS RR
	TYPE_WINSR = 65282,	///< Microsoft's WINS-R RR
	// Private use RR TYPE range: 65280 - 65534
	TYPE_BINDS = 65534,  ///< Bind9's Private Type Rec for signaling state of signing process
};

#define DNS_CLASS_IN 1
#define DNS_CLASS_ANY 255

enum DNS_AnswerType {
	DNS_QUESTION,
	DNS_ANSWER,
	DNS_AUTHORITY,
	DNS_ADDITIONAL,
};

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
// DNS EDNS0 Option Codes (OPT)
enum EDNS_OPT_Type {
	TYPE_LLQ = 1,			///< https://www.iana.org/go/draft-sekar-dns-llq-06
	TYPE_UL = 2,			///< http://files.dns-sd.org/draft-sekar-dns-ul.txt
	TYPE_NSID = 3,			///< RFC5001
	TYPE_DAU = 5,			///< RFC6975
	TYPE_DHU = 6,			///< RFC6975
	TYPE_N3U = 7,			///< RFC6975
	TYPE_ECS = 8,			///< RFC7871
	TYPE_EXPIRE = 9,		///< RFC7314
	TYPE_COOKIE = 10,		///< RFC7873
	TYPE_TCP_KA = 11,		///< RFC7828
	TYPE_PAD = 12,			///< RFC7830
	TYPE_CHAIN = 13,		///< RFC7901
	TYPE_KEY_TAG = 14,		///< RFC8145
	TYPE_ERROR = 15,		///< https://www.iana.org/go/draft-ietf-dnsop-extended-error-16
	TYPE_CLIENT_TAG = 16,	///< https://www.iana.org/go/draft-bellis-dnsop-edns-tags
	TYPE_SERVER_TAG = 17,	///< https://www.iana.org/go/draft-bellis-dnsop-edns-tags
	TYPE_DEVICE_ID = 26946	///< https://docs.umbrella.com/developer/networkdevices-api/identifying-dns-traffic2
};

enum DNSSEC_Algo {
	reserved0 = 0,
	RSA_MD5 = 1,          ///<	[RFC2537]  NOT RECOMMENDED
	Diffie_Hellman = 2,	///< [RFC2539]
	DSA_SHA1 = 3,	///< [RFC2536]  OPTIONAL
	Elliptic_Curve = 4,
	RSA_SHA1 = 5,	///< [RFC3110]  MANDATORY
	DSA_NSEC3_SHA1 = 6,
	RSA_SHA1_NSEC3_SHA1 = 7,
	RSA_SHA256 = 8,
	RSA_SHA512 = 10,
	GOST_R_34_10_2001 = 12,
	ECDSA_curveP256withSHA256 = 13,
	ECDSA_curveP384withSHA384 =14,
	Indirect = 252,	///<
	PrivateDNS = 253,	///<  OPTIONAL
	PrivateOID = 254,	///<  OPTIONAL
	reserved255 = 255,
};

enum DNSSEC_Digest {
	reserved = 0,
	SHA1 = 1,          ///< [RFC3110]  MANDATORY
	SHA256 = 2,
	GOST_R_34_11_94 = 3,
	SHA384 = 4,
};

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

struct EDNS_ECS {
	StringValPtr ecs_family;	///< EDNS client subnet address family
	uint16_t ecs_src_pfx_len;	///< EDNS client subnet source prefix length
	uint16_t ecs_scp_pfx_len;	///< EDNS client subnet scope prefix length
	IntrusivePtr<AddrVal> ecs_addr;	///< EDNS client subnet address
};

struct EDNS_TCP_KEEPALIVE {
	bool     keepalive_timeout_omitted; ///< whether the keepalive timeout is omitted
	uint16_t keepalive_timeout; ///< the timeout value (in 100ms) sent by the client/server
};

struct EDNS_COOKIE {
	zeek::String* client_cookie; ///< cookie value sent by the client (8 bytes)
	zeek::String* server_cookie; ///< cookie value sent by the server (0 or 8-32 bytes)
};

struct TSIG_DATA {
	String* alg_name;
	unsigned long time_s;
	unsigned short time_ms;
	String* sig;
	unsigned short fudge;
	unsigned short orig_id;
	unsigned short rr_error;
};

struct RRSIG_DATA {
	unsigned short type_covered;	// 16 : ExtractShort(data, len)
	unsigned short algorithm;		// 8
	unsigned short labels;			// 8
	uint32_t orig_ttl;				// 32
	unsigned long sig_exp;			// 32
	unsigned long sig_incep;		// 32
	unsigned short key_tag;			//16
	String* signer_name;
	String* signature;
};

struct DNSKEY_DATA {
	unsigned short dflags;			// 16 : ExtractShort(data, len)
	unsigned short dalgorithm;		// 8
	unsigned short dprotocol;		// 8
	String* public_key;			// Variable lenght Public Key
};

struct NSEC3_DATA {
	unsigned short nsec_flags;
	unsigned short nsec_hash_algo;
	unsigned short nsec_iter;
	unsigned short nsec_salt_len;
	String* nsec_salt;
	unsigned short nsec_hlen;
	String* nsec_hash;
	VectorValPtr bitmaps;
};

struct NSEC3PARAM_DATA {
	unsigned short nsec_flags;		// 8
	unsigned short nsec_hash_algo;	// 8
	unsigned short nsec_iter;		// 16 : ExtractShort(data, len)
	unsigned short nsec_salt_len;	// 8
	String* nsec_salt;				// Variable length salt
};

struct DS_DATA {
	unsigned short key_tag;			// 16 : ExtractShort(data, len)
	unsigned short algorithm;		// 8
	unsigned short digest_type;		// 8
	String* digest_val;			// Variable lenght Digest of DNSKEY RR
};

struct BINDS_DATA {
	unsigned short algorithm;		// 8 
	unsigned short key_id;			// 16 : ExtractShort(data, len)
	unsigned short removal_flag;	// 8
	String* complete_flag;			// 8
};

struct LOC_DATA {
	String* version;	// 8
	String* size;		// 8
	String* horiz_pre;	// 8
	String* vert_pre;	// 8
	unsigned long latitide;		// 32
	unsigned long longitude;	// 32
	unsigned long altitude;		// 32
};

class DNS_MsgInfo {
public:
	DNS_MsgInfo(DNS_RawMsgHdr* hdr, int is_query);

	RecordValPtr BuildHdrVal();
	RecordValPtr BuildAnswerVal();
	RecordValPtr BuildEDNS_Val();
	RecordValPtr BuildEDNS_ECS_Val(struct EDNS_ECS*);
	RecordValPtr BuildEDNS_TCP_KA_Val(struct EDNS_TCP_KEEPALIVE*);
	RecordValPtr BuildEDNS_COOKIE_Val(struct EDNS_COOKIE*);
	RecordValPtr BuildTSIG_Val(struct TSIG_DATA*);
	RecordValPtr BuildRRSIG_Val(struct RRSIG_DATA*);
	RecordValPtr BuildDNSKEY_Val(struct DNSKEY_DATA*);
	RecordValPtr BuildNSEC3_Val(struct NSEC3_DATA*);
	RecordValPtr BuildNSEC3PARAM_Val(struct NSEC3PARAM_DATA*);
	RecordValPtr BuildDS_Val(struct DS_DATA*);
	RecordValPtr BuildBINDS_Val(struct BINDS_DATA*);
	RecordValPtr BuildLOC_Val(struct LOC_DATA*);

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

	StringValPtr query_name;
	RR_Type atype;
	int aclass;	///< normally = 1, inet
	uint32_t ttl;

	DNS_AnswerType answer_type;
	int skip_event;		///< if true, don't generate corresponding events
	// int answer_count;	///< count of responders.  if >1 and not
				///< identical answer, there may be problems
	// uint32* addr;	///< cache value to pass back results
				///< for forward lookups
};

class DNS_Interpreter {
public:
	explicit DNS_Interpreter(analyzer::Analyzer* analyzer);

	void ParseMessage(const u_char* data, int len, int is_query);

	void Timeout()	{ }

protected:
	void EndMessage(detail::DNS_MsgInfo* msg);

	bool ParseQuestions(detail::DNS_MsgInfo* msg,
	                    const u_char*& data, int& len,
	                    const u_char* start);
	bool ParseAnswers(detail::DNS_MsgInfo* msg, int n,
	                  detail::DNS_AnswerType answer_type,
	                  const u_char*& data, int& len,
	                  const u_char* start);

	bool ParseQuestion(detail::DNS_MsgInfo* msg,
	                   const u_char*& data, int& len, const u_char* start);
	bool ParseAnswer(detail::DNS_MsgInfo* msg,
	                 const u_char*& data, int& len, const u_char* start);

	u_char* ExtractName(const u_char*& data, int& len,
	                    u_char* label, int label_len,
	                    const u_char* msg_start, bool downcase = true);
	bool ExtractLabel(const u_char*& data, int& len,
	                  u_char*& label, int& label_len,
	                  const u_char* msg_start);

	uint16_t ExtractShort(const u_char*& data, int& len);
	uint32_t ExtractLong(const u_char*& data, int& len);
	void ExtractOctets(const u_char*& data, int& len, String** p);

	String* ExtractStream(const u_char*& data, int& len, int sig_len);

	bool ParseRR_Name(detail::DNS_MsgInfo* msg,
	                  const u_char*& data, int& len, int rdlength,
	                  const u_char* msg_start);
	bool ParseRR_SOA(detail::DNS_MsgInfo* msg,
	                 const u_char*& data, int& len, int rdlength,
	                 const u_char* msg_start);
	bool ParseRR_MX(detail::DNS_MsgInfo* msg,
	                const u_char*& data, int& len, int rdlength,
	                const u_char* msg_start);
	bool ParseRR_NBS(detail::DNS_MsgInfo* msg,
	                 const u_char*& data, int& len, int rdlength,
	                 const u_char* msg_start);
	bool ParseRR_SRV(detail::DNS_MsgInfo* msg,
	                 const u_char*& data, int& len, int rdlength,
	                 const u_char* msg_start);
	bool ParseRR_EDNS(detail::DNS_MsgInfo* msg,
	                  const u_char*& data, int& len, int rdlength,
	                  const u_char* msg_start);
	bool ParseRR_EDNS_ECS(detail::DNS_MsgInfo* msg,
	                      const u_char*& data, int& len, int rdlength,
	                      const u_char* msg_start);
	bool ParseRR_A(detail::DNS_MsgInfo* msg,
	               const u_char*& data, int& len, int rdlength);
	bool ParseRR_AAAA(detail::DNS_MsgInfo* msg,
	                  const u_char*& data, int& len, int rdlength);
	bool ParseRR_WKS(detail::DNS_MsgInfo* msg,
	                 const u_char*& data, int& len, int rdlength);
	bool ParseRR_HINFO(detail::DNS_MsgInfo* msg,
	                   const u_char*& data, int& len, int rdlength);
	bool ParseRR_TXT(detail::DNS_MsgInfo* msg,
	                 const u_char*& data, int& len, int rdlength,
	                 const u_char* msg_start);
	bool ParseRR_SPF(detail::DNS_MsgInfo* msg,
	                 const u_char*& data, int& len, int rdlength,
	                 const u_char* msg_start);
	bool ParseRR_CAA(detail::DNS_MsgInfo* msg,
	                 const u_char*& data, int& len, int rdlength,
	                 const u_char* msg_start);
	bool ParseRR_TSIG(detail::DNS_MsgInfo* msg,
	                  const u_char*& data, int& len, int rdlength,
	                  const u_char* msg_start);
	bool ParseRR_RRSIG(detail::DNS_MsgInfo* msg,
	                   const u_char*& data, int& len, int rdlength,
	                   const u_char* msg_start);
	bool ParseRR_DNSKEY(detail::DNS_MsgInfo* msg,
	                    const u_char*& data, int& len, int rdlength,
	                    const u_char* msg_start);
	bool ParseRR_NSEC(detail::DNS_MsgInfo* msg,
	                  const u_char*& data, int& len, int rdlength,
	                  const u_char* msg_start);
	bool ParseRR_NSEC3(detail::DNS_MsgInfo* msg,
	                   const u_char*& data, int& len, int rdlength,
	                   const u_char* msg_start);
	bool ParseRR_NSEC3PARAM(detail::DNS_MsgInfo* msg,
	                   const u_char*& data, int& len, int rdlength,
	                   const u_char* msg_start);
	bool ParseRR_DS(detail::DNS_MsgInfo* msg,
	                const u_char*& data, int& len, int rdlength,
	                const u_char* msg_start);
	bool ParseRR_BINDS(detail::DNS_MsgInfo* msg,
	                const u_char*& data, int& len, int rdlength,
	                const u_char* msg_start);
	bool ParseRR_SSHFP(detail::DNS_MsgInfo* msg,
	                const u_char*& data, int& len, int rdlength,
	                const u_char* msg_start);
	bool ParseRR_LOC(detail::DNS_MsgInfo* msg,
	                const u_char*& data, int& len, int rdlength,
	                const u_char* msg_start);
	void SendReplyOrRejectEvent(detail::DNS_MsgInfo* msg, EventHandlerPtr event,
	                            const u_char*& data, int& len,
	                            String* question_name,
	                            String* original_name);

	analyzer::Analyzer* analyzer;
	bool first_message;
};

enum TCP_DNS_state {
	DNS_LEN_HI,		///< looking for the high-order byte of the length
	DNS_LEN_LO,		///< looking for the low-order byte of the length
	DNS_MESSAGE_BUFFER,	///< building up the message in the buffer
};

} // namespace detail

// Support analyzer which chunks the TCP stream into "packets".
// ### This should be merged with TCP_Contents_RPC.
class Contents_DNS final : public analyzer::tcp::TCP_SupportAnalyzer {
public:
	Contents_DNS(Connection* c, bool orig, detail::DNS_Interpreter* interp);
	~Contents_DNS() override;

	void Flush();		///< process any partially-received data

	detail::TCP_DNS_state State() const	{ return state; }

protected:
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void ProcessChunk(int& len, const u_char*& data, bool orig);

	detail::DNS_Interpreter* interp;

	u_char* msg_buf;
	int buf_n;		///< number of bytes in msg_buf
	int buf_len;		///< size of msg_buf
	int msg_size;		///< expected size of message
	detail::TCP_DNS_state state;
};

// Works for both TCP and UDP.
class DNS_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
	explicit DNS_Analyzer(Connection* conn);
	~DNS_Analyzer() override;

	void DeliverPacket(int len, const u_char* data, bool orig,
					uint64_t seq, const IP_Hdr* ip, int caplen) override;

	void Init() override;
	void Done() override;
	void ConnectionClosed(analyzer::tcp::TCP_Endpoint* endpoint,
	                      analyzer::tcp::TCP_Endpoint* peer, bool gen_event) override;
	void ExpireTimer(double t);

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new DNS_Analyzer(conn); }

protected:
	detail::DNS_Interpreter* interp;
	Contents_DNS* contents_dns_orig;
	Contents_DNS* contents_dns_resp;
};

} // namespace zeek::analyzer::dns

namespace analyzer::dns {

using DNS_Opcode [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DNS_Opcode.")]] = zeek::analyzer::dns::detail::DNS_Opcode;
constexpr auto DNS_OP_QUERY [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DNS_OP_QUERY.")]] = zeek::analyzer::dns::detail::DNS_OP_QUERY;
constexpr auto DNS_OP_IQUERY [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DNS_OP_IQUERY.")]] = zeek::analyzer::dns::detail::DNS_OP_IQUERY;
constexpr auto DNS_OP_SERVER_STATUS [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DNS_OP_SERVER_STATUS.")]] = zeek::analyzer::dns::detail::DNS_OP_SERVER_STATUS;
constexpr auto NETBIOS_REGISTRATION [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::NETBIOS_REGISTRATION.")]] = zeek::analyzer::dns::detail::NETBIOS_REGISTRATION;
constexpr auto NETBIOS_RELEASE [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::NETBIOS_RELEASE.")]] = zeek::analyzer::dns::detail::NETBIOS_RELEASE;
constexpr auto NETBIOS_WACK [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::NETBIOS_WACK.")]] = zeek::analyzer::dns::detail::NETBIOS_WACK;
constexpr auto NETBIOS_REFRESH [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::NETBIOS_REFRESH.")]] = zeek::analyzer::dns::detail::NETBIOS_REFRESH;

using DNS_Code [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DNS_Code.")]] = zeek::analyzer::dns::detail::DNS_Code;
constexpr auto DNS_CODE_OK [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DNS_CODE_OK.")]] = zeek::analyzer::dns::detail::DNS_CODE_OK;
constexpr auto DNS_CODE_FORMAT_ERR [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DNS_CODE_FORMAT_ERR.")]] = zeek::analyzer::dns::detail::DNS_CODE_FORMAT_ERR;
constexpr auto DNS_CODE_SERVER_FAIL [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DNS_CODE_SERVER_FAIL.")]] = zeek::analyzer::dns::detail::DNS_CODE_SERVER_FAIL;
constexpr auto DNS_CODE_NAME_ERR [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DNS_CODE_NAME_ERR.")]] = zeek::analyzer::dns::detail::DNS_CODE_NAME_ERR;
constexpr auto DNS_CODE_NOT_IMPL [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DNS_CODE_NOT_IMPL.")]] = zeek::analyzer::dns::detail::DNS_CODE_NOT_IMPL;
constexpr auto DNS_CODE_REFUSED [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DNS_CODE_REFUSED.")]] = zeek::analyzer::dns::detail::DNS_CODE_REFUSED;

using RR_Type [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::RR_Type.")]] = zeek::analyzer::dns::detail::RR_Type;
constexpr auto TYPE_A [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_A.")]] = zeek::analyzer::dns::detail::TYPE_A;
constexpr auto TYPE_NS [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_NS.")]] = zeek::analyzer::dns::detail::TYPE_NS;
constexpr auto TYPE_CNAME [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_CNAME.")]] = zeek::analyzer::dns::detail::TYPE_CNAME;
constexpr auto TYPE_SOA [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_SOA.")]] = zeek::analyzer::dns::detail::TYPE_SOA;
constexpr auto TYPE_WKS [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_WKS.")]] = zeek::analyzer::dns::detail::TYPE_WKS;
constexpr auto TYPE_PTR [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_PTR.")]] = zeek::analyzer::dns::detail::TYPE_PTR;
constexpr auto TYPE_HINFO [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_HINFO.")]] = zeek::analyzer::dns::detail::TYPE_HINFO;
constexpr auto TYPE_MX [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_MX.")]] = zeek::analyzer::dns::detail::TYPE_MX;
constexpr auto TYPE_TXT [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_TXT.")]] = zeek::analyzer::dns::detail::TYPE_TXT;
constexpr auto TYPE_SIG [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_SIG.")]] = zeek::analyzer::dns::detail::TYPE_SIG;
constexpr auto TYPE_KEY [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_KEY.")]] = zeek::analyzer::dns::detail::TYPE_KEY;
constexpr auto TYPE_PX [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_PX.")]] = zeek::analyzer::dns::detail::TYPE_PX;
constexpr auto TYPE_AAAA [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_AAAA.")]] = zeek::analyzer::dns::detail::TYPE_AAAA;
constexpr auto TYPE_NBS [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_NBS.")]] = zeek::analyzer::dns::detail::TYPE_NBS;
constexpr auto TYPE_SRV [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_SRV.")]] = zeek::analyzer::dns::detail::TYPE_SRV;
constexpr auto TYPE_NAPTR [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_NAPTR.")]] = zeek::analyzer::dns::detail::TYPE_NAPTR;
constexpr auto TYPE_KX [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_KX.")]] = zeek::analyzer::dns::detail::TYPE_KX;
constexpr auto TYPE_CERT [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_CERT.")]] = zeek::analyzer::dns::detail::TYPE_CERT;
constexpr auto TYPE_A6 [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_A6.")]] = zeek::analyzer::dns::detail::TYPE_A6;
constexpr auto TYPE_DNAME [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_DNAME.")]] = zeek::analyzer::dns::detail::TYPE_DNAME;
constexpr auto TYPE_EDNS [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_EDNS.")]] = zeek::analyzer::dns::detail::TYPE_EDNS;
constexpr auto TYPE_TKEY [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_TKEY.")]] = zeek::analyzer::dns::detail::TYPE_TKEY;
constexpr auto TYPE_TSIG [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_TSIG.")]] = zeek::analyzer::dns::detail::TYPE_TSIG;
constexpr auto TYPE_CAA [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_CAA.")]] = zeek::analyzer::dns::detail::TYPE_CAA;
constexpr auto TYPE_SSHFP [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_SSHFP.")]] = zeek::analyzer::dns::detail::TYPE_SSHFP;
constexpr auto TYPE_RRSIG [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_RRSIG.")]] = zeek::analyzer::dns::detail::TYPE_RRSIG;
constexpr auto TYPE_NSEC [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_NSEC.")]] = zeek::analyzer::dns::detail::TYPE_NSEC;
constexpr auto TYPE_DNSKEY [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_DNSKEY.")]] = zeek::analyzer::dns::detail::TYPE_DNSKEY;
constexpr auto TYPE_DS [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_DS.")]] = zeek::analyzer::dns::detail::TYPE_DS;
constexpr auto TYPE_BINDS [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_BINDS.")]] = zeek::analyzer::dns::detail::TYPE_BINDS;
constexpr auto TYPE_NSEC3 [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_NSEC3.")]] = zeek::analyzer::dns::detail::TYPE_NSEC3;
constexpr auto TYPE_NSEC3PARAM [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_NSEC3PARAM.")]] = zeek::analyzer::dns::detail::TYPE_NSEC3PARAM;
constexpr auto TYPE_LOC [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_LOC.")]] = zeek::analyzer::dns::detail::TYPE_LOC;
constexpr auto TYPE_SPF [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_SPF.")]] = zeek::analyzer::dns::detail::TYPE_SPF;
constexpr auto TYPE_AXFR [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_AXFR.")]] = zeek::analyzer::dns::detail::TYPE_AXFR;
constexpr auto TYPE_ALL [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_ALL.")]] = zeek::analyzer::dns::detail::TYPE_ALL;
constexpr auto TYPE_WINS [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_WINS.")]] = zeek::analyzer::dns::detail::TYPE_WINS;
constexpr auto TYPE_WINSR [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_WINSR.")]] = zeek::analyzer::dns::detail::TYPE_WINSR;

using DNS_AnswerType [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DNS_AnswerType.")]] = zeek::analyzer::dns::detail::DNS_AnswerType;
constexpr auto DNS_QUESTION [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DNS_QUESTION.")]] = zeek::analyzer::dns::detail::DNS_QUESTION;
constexpr auto DNS_ANSWER [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DNS_ANSWER.")]] = zeek::analyzer::dns::detail::DNS_ANSWER;
constexpr auto DNS_AUTHORITY [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DNS_AUTHORITY.")]] = zeek::analyzer::dns::detail::DNS_AUTHORITY;
constexpr auto DNS_ADDITIONAL [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DNS_ADDITIONAL.")]] = zeek::analyzer::dns::detail::DNS_ADDITIONAL;

using EDNS_OPT_Type [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::EDNS_OPT_Type.")]] = zeek::analyzer::dns::detail::EDNS_OPT_Type;
constexpr auto TYPE_LLQ [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_LLQ.")]] = zeek::analyzer::dns::detail::TYPE_LLQ;
constexpr auto TYPE_UL [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_UL.")]] = zeek::analyzer::dns::detail::TYPE_UL;
constexpr auto TYPE_NSID [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_NSID.")]] = zeek::analyzer::dns::detail::TYPE_NSID;
constexpr auto TYPE_DAU [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_DAU.")]] = zeek::analyzer::dns::detail::TYPE_DAU;
constexpr auto TYPE_DHU [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_DHU.")]] = zeek::analyzer::dns::detail::TYPE_DHU;
constexpr auto TYPE_N3U [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_N3U.")]] = zeek::analyzer::dns::detail::TYPE_N3U;
constexpr auto TYPE_ECS [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_ECS.")]] = zeek::analyzer::dns::detail::TYPE_ECS;
constexpr auto TYPE_EXPIRE [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_EXPIRE.")]] = zeek::analyzer::dns::detail::TYPE_EXPIRE;
constexpr auto TYPE_TCP_KA [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_TCP_KA.")]] = zeek::analyzer::dns::detail::TYPE_TCP_KA;
constexpr auto TYPE_PAD [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_PAD.")]] = zeek::analyzer::dns::detail::TYPE_PAD;
constexpr auto TYPE_CHAIN [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_CHAIN.")]] = zeek::analyzer::dns::detail::TYPE_CHAIN;
constexpr auto TYPE_KEY_TAG [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_KEY_TAG.")]] = zeek::analyzer::dns::detail::TYPE_KEY_TAG;
constexpr auto TYPE_ERROR [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_ERROR.")]] = zeek::analyzer::dns::detail::TYPE_ERROR;
constexpr auto TYPE_CLIENT_TAG [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_CLIENT_TAG.")]] = zeek::analyzer::dns::detail::TYPE_CLIENT_TAG;
constexpr auto TYPE_SERVER_TAG [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_SERVER_TAG.")]] = zeek::analyzer::dns::detail::TYPE_SERVER_TAG;
constexpr auto TYPE_DEVICE_ID [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TYPE_DEVICE_ID.")]] = zeek::analyzer::dns::detail::TYPE_DEVICE_ID;

using DNSSEC_Algo [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DNSSEC_Algo.")]] = zeek::analyzer::dns::detail::DNSSEC_Algo;
constexpr auto reserved0 [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::reserved0.")]] = zeek::analyzer::dns::detail::reserved0;
constexpr auto RSA_MD5 [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::RSA_MD5.")]] = zeek::analyzer::dns::detail::RSA_MD5;
constexpr auto Diffie_Hellman [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::Diffie_Hellman.")]] = zeek::analyzer::dns::detail::Diffie_Hellman;
constexpr auto DSA_SHA1 [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DSA_SHA1.")]] = zeek::analyzer::dns::detail::DSA_SHA1;
constexpr auto Elliptic_Curve [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::Elliptic_Curve.")]] = zeek::analyzer::dns::detail::Elliptic_Curve;
constexpr auto RSA_SHA1 [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::RSA_SHA1.")]] = zeek::analyzer::dns::detail::RSA_SHA1;
constexpr auto DSA_NSEC3_SHA1 [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DSA_NSEC3_SHA1.")]] = zeek::analyzer::dns::detail::DSA_NSEC3_SHA1;
constexpr auto RSA_SHA1_NSEC3_SHA1 [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::RSA_SHA1_NSEC3_SHA1.")]] = zeek::analyzer::dns::detail::RSA_SHA1_NSEC3_SHA1;
constexpr auto RSA_SHA256 [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::RSA_SHA256.")]] = zeek::analyzer::dns::detail::RSA_SHA256;
constexpr auto RSA_SHA512 [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::RSA_SHA512.")]] = zeek::analyzer::dns::detail::RSA_SHA512;
constexpr auto GOST_R_34_10_2001 [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::GOST_R_34_10_2001.")]] = zeek::analyzer::dns::detail::GOST_R_34_10_2001;
constexpr auto ECDSA_curveP256withSHA256 [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::ECDSA_curveP256withSHA256.")]] = zeek::analyzer::dns::detail::ECDSA_curveP256withSHA256;
constexpr auto ECDSA_curveP384withSHA384 [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::ECDSA_curveP384withSHA384.")]] = zeek::analyzer::dns::detail::ECDSA_curveP384withSHA384;
constexpr auto Indirect [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::Indirect.")]] = zeek::analyzer::dns::detail::Indirect;
constexpr auto PrivateDNS [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::PrivateDNS.")]] = zeek::analyzer::dns::detail::PrivateDNS;
constexpr auto PrivateOID [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::PrivateOID.")]] = zeek::analyzer::dns::detail::PrivateOID;
constexpr auto reserved255 [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::reserved255.")]] = zeek::analyzer::dns::detail::reserved255;

using DNSSEC_Digest [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DNSSEC_Digest.")]] = zeek::analyzer::dns::detail::DNSSEC_Digest;
constexpr auto reserved [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::reserved.")]] = zeek::analyzer::dns::detail::reserved;
constexpr auto SHA1 [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::SHA1.")]] = zeek::analyzer::dns::detail::SHA1;
constexpr auto SHA256 [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::SHA256.")]] = zeek::analyzer::dns::detail::SHA256;
constexpr auto GOST_R_34_11_94 [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::GOST_R_34_11_94.")]] = zeek::analyzer::dns::detail::GOST_R_34_11_94;
constexpr auto SHA384 [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::SHA384.")]] = zeek::analyzer::dns::detail::SHA384;

using DNS_RawMsgHdr [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DNS_RawMsgHdr.")]] = zeek::analyzer::dns::detail::DNS_RawMsgHdr;
using EDNS_ADDITIONAL [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::EDNS_ADDITIONAL.")]] = zeek::analyzer::dns::detail::EDNS_ADDITIONAL;
using EDNS_ECS [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::EDNS_ECS.")]] = zeek::analyzer::dns::detail::EDNS_ECS;
using TSIG_DATA [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TSIG_DATA.")]] = zeek::analyzer::dns::detail::TSIG_DATA;
using RRSIG_DATA [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::RRSIG_DATA.")]] = zeek::analyzer::dns::detail::RRSIG_DATA;
using DNSKEY_DATA [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DNSKEY_DATA.")]] = zeek::analyzer::dns::detail::DNSKEY_DATA;
using NSEC3_DATA [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::NSEC3_DATA.")]] = zeek::analyzer::dns::detail::NSEC3_DATA;
using NSEC3PARAM_DATA [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::NSEC3PARAM_DATA.")]] = zeek::analyzer::dns::detail::NSEC3PARAM_DATA;
using DS_DATA [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DS_DATA.")]] = zeek::analyzer::dns::detail::DS_DATA;
using BINDS_DATA [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::BINDS_DATA.")]] = zeek::analyzer::dns::detail::BINDS_DATA;
using LOC_DATA [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::LOC_DATA.")]] = zeek::analyzer::dns::detail::LOC_DATA;
using DNS_MsgInfo [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DNS_MsgInfo.")]] = zeek::analyzer::dns::detail::DNS_MsgInfo;

using TCP_DNS_state [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::TCP_DNS_state.")]] = zeek::analyzer::dns::detail::TCP_DNS_state;
constexpr auto DNS_LEN_HI [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DNS_LEN_HI.")]] = zeek::analyzer::dns::detail::DNS_LEN_HI;
constexpr auto DNS_LEN_LO [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DNS_LEN_LO.")]] = zeek::analyzer::dns::detail::DNS_LEN_LO;
constexpr auto DNS_MESSAGE_BUFFER [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DNS_MESSAGE_BUFFER.")]] = zeek::analyzer::dns::detail::DNS_MESSAGE_BUFFER;

using DNS_Interpreter [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::detail::DNS_Interpreter.")]] = zeek::analyzer::dns::detail::DNS_Interpreter;
using Contents_DNS [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::Contents_DNS.")]] = zeek::analyzer::dns::Contents_DNS;
using DNS_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::dns::DNS_Analyzer.")]] = zeek::analyzer::dns::DNS_Analyzer;

} // namespace analyzer::dns
