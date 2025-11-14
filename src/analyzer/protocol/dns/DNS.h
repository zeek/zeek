// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace zeek::analyzer::dns {
namespace detail {

enum DNS_Opcode : uint8_t {
    DNS_OP_QUERY = 0,  ///< standard query
    DNS_OP_IQUERY = 1, ///< reverse query

    // ### Is server status 2 or 3? RFC 1035 says it's 2
    // DNS_OP_SERVER_STATUS = 3,	///< server status request
    DNS_OP_SERVER_STATUS = 2, ///< server status request

    DNS_OP_NOTIFY = 4,         ///< RFC 1996
    DNS_OP_DYNAMIC_UPDATE = 5, ///< RFC 2136
    DNS_OP_DSO = 6,            ///< RFC 8490

    // Netbios operations (query = 0).
    NETBIOS_REGISTRATION = 5,
    NETBIOS_RELEASE = 6,
    NETBIOS_WACK = 7, // wait for ACK
    NETBIOS_REFRESH = 8,
};

enum DNS_Code : uint16_t {
    DNS_CODE_OK = 0,           ///< no error
    DNS_CODE_FORMAT_ERR = 1,   ///< format error
    DNS_CODE_SERVER_FAIL = 2,  ///< server failure
    DNS_CODE_NAME_ERR = 3,     ///< no such domain
    DNS_CODE_NOT_IMPL = 4,     ///< not implemented
    DNS_CODE_REFUSED = 5,      ///< refused
    DNS_CODE_YXDOMAIN = 6,     ///< name exists when it should not (RFC 2136)
    DNS_CODE_YXRRSET = 7,      ///< rr set exists when it should not (RFC 2136)
    DNS_CODE_NXRRSET = 8,      ///< rr set that should exist does not (RFC 2136)
    DNS_CODE_NOTAUTH = 9,      ///< server not authoritative for zone (RFC 2136), or not authorized (RFC 8945)
    DNS_CODE_NOT_ZONE = 10,    ///< name not contained in zone (RFC 2136)
    DNS_CODE_RESERVED = 65535, ///< Force clang-tidy to accept this enum being 16 bits
};

enum RR_Type : uint16_t {
    TYPE_A = 1,      ///< host address
    TYPE_NS = 2,     ///< authoritative name server
    TYPE_CNAME = 5,  ///< canonical name
    TYPE_SOA = 6,    ///< start of authority
    TYPE_WKS = 11,   ///< well known service
    TYPE_PTR = 12,   ///< domain name pointer
    TYPE_HINFO = 13, ///< host information
    TYPE_MX = 15,    ///< mail routing information
    TYPE_TXT = 16,   ///< text strings
    TYPE_SIG = 24,   ///< digital signature (RFC 2535)
    TYPE_KEY = 25,   ///< public key (RFC 2535)
    TYPE_PX = 26,    ///< pointer to X.400/RFC822 mapping info (RFC 1664)
    TYPE_AAAA = 28,  ///< IPv6 address (RFC 1886)
    TYPE_LOC = 29,   ///< Location information about hosts (RFC 1876)
    TYPE_NBS = 32,   ///< Netbios name (RFC 1002)
    TYPE_SRV = 33,   ///< service location (RFC 2052)
    TYPE_NAPTR = 35, ///< naming authority pointer (RFC 2168)
    TYPE_KX = 36,    ///< Key Exchange (RFC 2230)
    TYPE_CERT = 37,  ///< Certificate (RFC 2538)
    TYPE_A6 = 38,    ///< IPv6 address with indirection (RFC 2874)
    TYPE_DNAME = 39, ///< Non-terminal DNS name redirection (RFC 2672)
    TYPE_EDNS = 41,  ///< OPT pseudo-RR (RFC 2671)
    TYPE_SSHFP = 44, ///< SSH Public Key Fingerprint (RFC 4255)
    TYPE_TKEY = 249, ///< Transaction Key (RFC 2930)
    TYPE_TSIG = 250, ///< Transaction Signature (RFC 2845)
    TYPE_CAA = 257,  ///< Certification Authority Authorization (RFC 6844)
    // DNSSEC RR's
    TYPE_RRSIG = 46,  ///< RR Signature record type (RFC4043)
    TYPE_NSEC = 47,   ///< Next Secure record (RFC4043)
    TYPE_DNSKEY = 48, ///< DNS Key record (RFC 4034)
    TYPE_DS = 43,     ///< Delegation signer (RFC 4034)
    TYPE_NSEC3 = 50,
    TYPE_NSEC3PARAM = 51, ///< Contains the NSEC3 parameters (RFC 5155)
    TYPE_SVCB = 64,       ///< Service Binding (RFC draft:
                          ///< https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-07#section-1.1)
    TYPE_HTTPS = 65,      ///< HTTPS record (HTTPS specific SVCB resource record)
    // Obsoleted
    TYPE_SPF = 99, ///< Alternative: storing SPF data in TXT records, using the same format (RFC
                   ///< 4408). Support for it was discontinued in RFC 7208
    // The following are only valid in queries.
    TYPE_AXFR = 252,
    TYPE_ALL = 255,
    TYPE_WINS = 65281,  ///< Microsoft's WINS RR
    TYPE_WINSR = 65282, ///< Microsoft's WINS-R RR
    // Private use RR TYPE range: 65280 - 65534
    TYPE_BINDS = 65534, ///< Bind9's Private Type Rec for signaling state of signing process
};

enum DNS_Class : uint16_t {
    DNS_CLASS_IN = 1,
    DNS_CLASS_NONE = 254, ///< RFC2136
    DNS_CLASS_ANY = 255,
    DNS_CLASS_RESERVED = 65535, ///< Force clang-tidy to accept this enum being 16 bits
};

enum DNS_AnswerType : uint8_t {
    DNS_QUESTION,
    DNS_ANSWER,
    DNS_AUTHORITY,
    DNS_ADDITIONAL,
    DNS_PREREQUISITES,
    DNS_UPDATES,
};

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
// DNS EDNS0 Option Codes (OPT)
enum EDNS_OPT_Type : uint16_t {
    TYPE_LLQ = 1,          ///< https://www.iana.org/go/draft-sekar-dns-llq-06
    TYPE_UL = 2,           ///< http://files.dns-sd.org/draft-sekar-dns-ul.txt
    TYPE_NSID = 3,         ///< RFC5001
    TYPE_DAU = 5,          ///< RFC6975
    TYPE_DHU = 6,          ///< RFC6975
    TYPE_N3U = 7,          ///< RFC6975
    TYPE_ECS = 8,          ///< RFC7871
    TYPE_EXPIRE = 9,       ///< RFC7314
    TYPE_COOKIE = 10,      ///< RFC7873
    TYPE_TCP_KA = 11,      ///< RFC7828
    TYPE_PAD = 12,         ///< RFC7830
    TYPE_CHAIN = 13,       ///< RFC7901
    TYPE_KEY_TAG = 14,     ///< RFC8145
    TYPE_ERROR = 15,       ///< https://www.iana.org/go/draft-ietf-dnsop-extended-error-16
    TYPE_CLIENT_TAG = 16,  ///< https://www.iana.org/go/draft-bellis-dnsop-edns-tags
    TYPE_SERVER_TAG = 17,  ///< https://www.iana.org/go/draft-bellis-dnsop-edns-tags
    TYPE_DEVICE_ID = 26946 ///< https://docs.umbrella.com/developer/networkdevices-api/identifying-dns-traffic2
};

enum DNSSEC_Algo : uint8_t {
    reserved0 = 0,
    RSA_MD5 = 1,        ///<	[RFC2537]  NOT RECOMMENDED
    Diffie_Hellman = 2, ///< [RFC2539]
    DSA_SHA1 = 3,       ///< [RFC2536]  OPTIONAL
    Elliptic_Curve = 4,
    RSA_SHA1 = 5, ///< [RFC3110]  MANDATORY
    DSA_NSEC3_SHA1 = 6,
    RSA_SHA1_NSEC3_SHA1 = 7,
    RSA_SHA256 = 8,
    RSA_SHA512 = 10,
    GOST_R_34_10_2001 = 12,
    ECDSA_curveP256withSHA256 = 13,
    ECDSA_curveP384withSHA384 = 14,
    Ed25519 = 15,
    Ed448 = 16,
    Indirect = 252,   ///<
    PrivateDNS = 253, ///<  OPTIONAL
    PrivateOID = 254, ///<  OPTIONAL
    reserved255 = 255,
};

enum DNSSEC_Digest : uint8_t {
    reserved = 0,
    SHA1 = 1, ///< [RFC3110]  MANDATORY
    SHA256 = 2,
    GOST_R_34_11_94 = 3,
    SHA384 = 4,
};

// SVCB/HTTPS SvcParam keys as defined in
// https://datatracker.ietf.org/doc/html/rfc9460#name-initial-contents
// Keep in sync with scripts/base/protocols/dns/consts.zeek svcparam_keys.
enum SVCPARAM_Key : uint8_t {
    mandatory = 0,
    alpn = 1,
    no_default_alpn = 2,
    port = 3,
    ipv4hint = 4,
    ech = 5,
    ipv6hint = 6,
};

struct DNS_RawMsgHdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qd_zo_count;
    uint16_t an_pr_count;
    uint16_t ns_up_count;
    uint16_t arcount;
};

struct EDNS_ADDITIONAL {    // size
    uint16_t name;          // -
    uint16_t type;          // 16 : ExtractShort(data, len)
    uint16_t payload_size;  // 16
    uint8_t extended_rcode; // 8
    uint8_t version;        // 8
    uint16_t z;             // 16
    uint16_t rdata_len;     // 16
};

struct EDNS_ECS {
    StringValPtr ecs_family;        ///< EDNS client subnet address family
    uint16_t ecs_src_pfx_len;       ///< EDNS client subnet source prefix length
    uint16_t ecs_scp_pfx_len;       ///< EDNS client subnet scope prefix length
    IntrusivePtr<AddrVal> ecs_addr; ///< EDNS client subnet address
};

struct EDNS_TCP_KEEPALIVE {
    bool keepalive_timeout_omitted; ///< whether the keepalive timeout is omitted
    uint16_t keepalive_timeout;     ///< the timeout value (in 100ms) sent by the client/server
};

struct EDNS_COOKIE {
    zeek::String* client_cookie; ///< cookie value sent by the client (8 bytes)
    zeek::String* server_cookie; ///< cookie value sent by the server (0 or 8-32 bytes)
};

struct TKEY_DATA {
    String* alg_name;
    uint32_t inception;
    uint32_t expiration;
    uint16_t mode;
    uint16_t error;
    String* key;
};

struct TSIG_DATA {
    String* alg_name;
    uint32_t time_s;
    uint16_t time_ms;
    String* sig;
    uint16_t fudge;
    uint16_t orig_id;
    uint16_t rr_error;
};

struct RRSIG_DATA {
    uint16_t type_covered; // 16 : ExtractShort(data, len)
    uint8_t algorithm;     // 8
    uint8_t labels;        // 8
    uint32_t orig_ttl;     // 32
    uint32_t sig_exp;      // 32
    uint32_t sig_incep;    // 32
    uint16_t key_tag;      // 16
    String* signer_name;
    String* signature;
};

struct DNSKEY_DATA {
    uint16_t dflags;    // 16 : ExtractShort(data, len)
    uint8_t dalgorithm; // 8
    uint8_t dprotocol;  // 8
    String* public_key; // Variable length Public Key
};

struct NSEC3_DATA {
    uint16_t nsec_flags;
    uint16_t nsec_hash_algo;
    uint16_t nsec_iter;
    uint16_t nsec_salt_len;
    String* nsec_salt;
    uint16_t nsec_hlen;
    String* nsec_hash;
    VectorValPtr bitmaps;
};

struct NSEC3PARAM_DATA {
    uint8_t nsec_flags;     // 8
    uint8_t nsec_hash_algo; // 8
    uint16_t nsec_iter;     // 16 : ExtractShort(data, len)
    uint8_t nsec_salt_len;  // 8
    String* nsec_salt;      // Variable length salt
};

struct DS_DATA {
    uint16_t key_tag;    // 16 : ExtractShort(data, len)
    uint8_t algorithm;   // 8
    uint8_t digest_type; // 8
    String* digest_val;  // Variable length Digest of DNSKEY RR
};

struct BINDS_DATA {
    uint8_t algorithm;     // 8
    uint8_t removal_flag;  // 8
    uint16_t key_id;       // 16 : ExtractShort(data, len)
    uint8_t complete_flag; // 8
};

struct LOC_DATA {
    uint8_t version;    // 8
    uint8_t size;       // 8
    uint8_t horiz_pre;  // 8
    uint8_t vert_pre;   // 8
    uint32_t latitude;  // 32
    uint32_t longitude; // 32
    uint32_t altitude;  // 32
};

struct SVCB_DATA {
    uint16_t svc_priority; // 2
    StringValPtr target_name;
    VectorValPtr svc_params;
};

class DNS_MsgInfo final {
public:
    DNS_MsgInfo(DNS_RawMsgHdr* hdr, bool is_query, bool is_netbios);

    RecordValPtr BuildHdrVal();
    RecordValPtr BuildAnswerVal();
    RecordValPtr BuildEDNS_Val();
    RecordValPtr BuildEDNS_ECS_Val(struct EDNS_ECS*);
    RecordValPtr BuildEDNS_TCP_KA_Val(struct EDNS_TCP_KEEPALIVE*);
    RecordValPtr BuildEDNS_COOKIE_Val(struct EDNS_COOKIE*);
    RecordValPtr BuildTKEY_Val(struct TKEY_DATA*);
    RecordValPtr BuildTSIG_Val(struct TSIG_DATA*);
    RecordValPtr BuildRRSIG_Val(struct RRSIG_DATA*);
    RecordValPtr BuildDNSKEY_Val(struct DNSKEY_DATA*);
    RecordValPtr BuildNSEC3_Val(struct NSEC3_DATA*);
    RecordValPtr BuildNSEC3PARAM_Val(struct NSEC3PARAM_DATA*);
    RecordValPtr BuildDS_Val(struct DS_DATA*);
    RecordValPtr BuildBINDS_Val(struct BINDS_DATA*);
    RecordValPtr BuildLOC_Val(struct LOC_DATA*);
    RecordValPtr BuildSVCB_Val(const struct SVCB_DATA&);

    uint16_t id;
    uint8_t opcode;                 ///< query type, see DNS_Opcode
    uint16_t rcode;                 ///< return code, see DNS_Code
    bool QR;                        ///< query record flag
    bool AA;                        ///< authoritative answer flag
    bool TC;                        ///< truncated - size > 512 bytes for udp
    bool RD;                        ///< recursion desired
    bool RA;                        ///< recursion available
    uint8_t Z;                      ///< 3 bit field (includes AD and CD)
    bool AD;                        ///< authentic data
    bool CD;                        ///< checking disabled
    uint16_t qd_zo_count;           ///< number of questions (or zones for dynamic update)
    uint16_t an_pr_count;           ///< number of answers (or prerequisites for dynamic update)
    uint16_t ns_up_count;           ///< number of authority RRs (or updates for dynamic update)
    uint16_t arcount;               ///< number of additional RRs
    bool is_query = false;          ///< whether it came from the session initiator
    bool skip_event = false;        ///< if true, don't generate corresponding events
    bool is_dynamic_update = false; ///< whether this message is a dynamic update
    bool is_netbios = false;        ///< whether this request is from netbios

    StringValPtr query_name;
    RR_Type atype = TYPE_ALL;
    uint16_t aclass = 0; ///< normally = 1, inet
    uint32_t ttl = 0;
    uint16_t zclass = 0; ///< class of the zone for dynamic updates

    DNS_AnswerType answer_type = DNS_QUESTION;
};

class DNS_Interpreter final {
public:
    explicit DNS_Interpreter(analyzer::Analyzer* analyzer);

    void ParseMessage(const u_char* data, int len, int is_query);

    void Timeout() {}

private:
    void EndMessage(detail::DNS_MsgInfo* msg);

    bool ParseQuestions(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, const u_char* start);
    bool ParseAnswers(detail::DNS_MsgInfo* msg, int n, detail::DNS_AnswerType answer_type, const u_char*& data,
                      int& len, const u_char* start);

    bool ParseQuestion(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, const u_char* start);
    bool ParseAnswerHeader(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, const u_char* msg_start);
    bool ParseAnswer(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, const u_char* start);

    u_char* ExtractName(const u_char*& data, int& len, u_char* label, int label_len, const u_char* msg_start,
                        bool downcase = true);
    bool ExtractLabel(const u_char*& data, int& len, u_char*& label, int& label_len, const u_char* msg_start);

    uint8_t ExtractByte(const u_char*& data, int& len);
    uint16_t ExtractShort(const u_char*& data, int& len);
    uint32_t ExtractLong(const u_char*& data, int& len);
    void ExtractOctets(const u_char*& data, int& len, String** p);

    String* ExtractStream(const u_char*& data, int& len, int sig_len);

    VectorValPtr Parse_SvcParams(const u_char*& data, int& len, int svc_params_len);

    bool ParseRR_Name(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_SOA(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_MX(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_NBS(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_SRV(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_NAPTR(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_EDNS(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_EDNS_ECS(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength,
                          const u_char* msg_start);
    bool ParseRR_A(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength);
    bool ParseRR_AAAA(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength);
    bool ParseRR_WKS(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength);
    bool ParseRR_HINFO(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength);
    bool ParseRR_TXT(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_SPF(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_CAA(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_TKEY(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_TSIG(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_RRSIG(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_DNSKEY(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_NSEC(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_NSEC3(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_NSEC3PARAM(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength,
                            const u_char* msg_start);
    bool ParseRR_DS(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_BINDS(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_SSHFP(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_LOC(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_SVCB(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start,
                      const RR_Type& svcb_type);
    void SendReplyOrRejectEvent(detail::DNS_MsgInfo* msg, EventHandlerPtr event, const u_char*& data, int& len,
                                String* question_name, String* original_name);

    analyzer::Analyzer* analyzer = nullptr;
    bool first_message = true;
    bool is_netbios = false;
};

enum TCP_DNS_state : uint8_t {
    DNS_LEN_HI,         ///< looking for the high-order byte of the length
    DNS_LEN_LO,         ///< looking for the low-order byte of the length
    DNS_MESSAGE_BUFFER, ///< building up the message in the buffer
};

} // namespace detail

// Support analyzer which chunks the TCP stream into "packets".
// ### This should be merged with TCP_Contents_RPC.
class Contents_DNS final : public analyzer::tcp::TCP_SupportAnalyzer {
public:
    Contents_DNS(Connection* c, bool orig, detail::DNS_Interpreter* interp);
    ~Contents_DNS() override;

    void Flush(); ///< process any partially-received data

    detail::TCP_DNS_state State() const { return state; }

protected:
    void DeliverStream(int len, const u_char* data, bool orig) override;
    void ProcessChunk(int& len, const u_char*& data, bool orig);

    detail::DNS_Interpreter* interp;

    u_char* msg_buf;
    int buf_n;    ///< number of bytes in msg_buf
    int buf_len;  ///< size of msg_buf
    int msg_size; ///< expected size of message
    detail::TCP_DNS_state state;
};

// Works for both TCP and UDP.
class DNS_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
    explicit DNS_Analyzer(Connection* conn);
    ~DNS_Analyzer() override;

    void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen) override;

    void Done() override;
    void ConnectionClosed(analyzer::tcp::TCP_Endpoint* endpoint, analyzer::tcp::TCP_Endpoint* peer,
                          bool gen_event) override;
    void ExpireTimer(double t);

    static analyzer::Analyzer* Instantiate(Connection* conn) { return new DNS_Analyzer(conn); }

protected:
    detail::DNS_Interpreter* interp;
    Contents_DNS* contents_dns_orig;
    Contents_DNS* contents_dns_resp;
};

} // namespace zeek::analyzer::dns
