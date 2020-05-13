// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"
#include "DNS.h"

#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "BroString.h"
#include "NetVar.h"
#include "Sessions.h"
#include "Event.h"
#include "Net.h"

#include "events.bif.h"

using namespace analyzer::dns;

DNS_Interpreter::DNS_Interpreter(analyzer::Analyzer* arg_analyzer)
	{
	analyzer = arg_analyzer;
	first_message = true;
	}

void DNS_Interpreter::ParseMessage(const u_char* data, int len, int is_query)
	{
	int hdr_len = sizeof(DNS_RawMsgHdr);

	if ( len < hdr_len )
		{
		analyzer->Weird("DNS_truncated_len_lt_hdr_len");
		return;
		}

	DNS_MsgInfo msg((DNS_RawMsgHdr*) data, is_query);

	if ( first_message && msg.QR && is_query == 1 )
		{
		is_query = msg.is_query = 0;

		if ( ! analyzer->Conn()->RespAddr().IsMulticast() )
			analyzer->Conn()->FlipRoles();
		}

	first_message = false;

	if ( dns_message )
		analyzer->EnqueueConnEvent(dns_message,
			analyzer->ConnVal(),
			val_mgr->Bool(is_query),
			msg.BuildHdrVal(),
			val_mgr->Count(len)
		);

	// There is a great deal of non-DNS traffic that runs on port 53.
	// This should weed out most of it.
	if ( dns_max_queries > 0 && msg.qdcount > dns_max_queries )
		{
		analyzer->ProtocolViolation("DNS_Conn_count_too_large");
		analyzer->Weird("DNS_Conn_count_too_large");
		EndMessage(&msg);
		return;
		}

	const u_char* msg_start = data;	// needed for interpreting compression

	data += hdr_len;
	len -= hdr_len;

	if ( ! ParseQuestions(&msg, data, len, msg_start) )
		{
		EndMessage(&msg);
		return;
		}

	if ( ! ParseAnswers(&msg, msg.ancount, DNS_ANSWER,
				data, len, msg_start) )
		{
		EndMessage(&msg);
		return;
		}

	analyzer->ProtocolConfirmation();

	AddrVal server(analyzer->Conn()->RespAddr());

	int skip_auth = dns_skip_all_auth;
	int skip_addl = dns_skip_all_addl;
	if ( msg.ancount > 0 )
		{ // We did an answer, so can potentially skip auth/addl.
		static auto dns_skip_auth = zeek::id::lookup_val<TableVal>("dns_skip_auth");
		static auto dns_skip_addl = zeek::id::lookup_val<TableVal>("dns_skip_addl");

		skip_auth = skip_auth || msg.nscount == 0 ||
				dns_skip_auth->Lookup(&server);
		skip_addl = skip_addl || msg.arcount == 0 ||
				dns_skip_addl->Lookup(&server);
		}

	if ( skip_auth && skip_addl )
		{
		// No point doing further work parsing the message.
		EndMessage(&msg);
		return;
		}

	msg.skip_event = skip_auth;
	if ( ! ParseAnswers(&msg, msg.nscount, DNS_AUTHORITY,
				data, len, msg_start) )
		{
		EndMessage(&msg);
		return;
		}

	if ( skip_addl )
		{
		// No point doing further work parsing the message.
		EndMessage(&msg);
		return;
		}

	msg.skip_event = skip_addl;
	if ( ! ParseAnswers(&msg, msg.arcount, DNS_ADDITIONAL,
				data, len, msg_start) )
		{
		EndMessage(&msg);
		return;
		}

	EndMessage(&msg);
	}

void DNS_Interpreter::EndMessage(DNS_MsgInfo* msg)
	{
	if ( dns_end )
		analyzer->EnqueueConnEvent(dns_end,
			analyzer->ConnVal(),
			msg->BuildHdrVal()
		);
	}

bool DNS_Interpreter::ParseQuestions(DNS_MsgInfo* msg,
				const u_char*& data, int& len,
				const u_char* msg_start)
	{
	int n = msg->qdcount;

	while ( n > 0 && ParseQuestion(msg, data, len, msg_start) )
		--n;
	return n == 0;
	}

bool DNS_Interpreter::ParseAnswers(DNS_MsgInfo* msg, int n, DNS_AnswerType atype,
				const u_char*& data, int& len,
				const u_char* msg_start)
	{
	msg->answer_type = atype;

	while ( n > 0 && ParseAnswer(msg, data, len, msg_start) )
		--n;

	return n == 0;
	}

bool DNS_Interpreter::ParseQuestion(DNS_MsgInfo* msg,
				const u_char*& data, int& len,
				const u_char* msg_start)
	{
	u_char name[513];
	int name_len = sizeof(name) - 1;

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start);
	if ( ! name_end )
		return false;

	if ( len < int(sizeof(short)) * 2 )
		{
		analyzer->Weird("DNS_truncated_quest_too_short");
		return false;
		}

	EventHandlerPtr dns_event = nullptr;

	if ( msg->QR == 0 )
		dns_event = dns_request;

	else if ( msg->QR == 1 &&
		  msg->ancount == 0 && msg->nscount == 0 && msg->arcount == 0 )
		// Service rejected in some fashion, and it won't be reported
		// via a returned RR because there aren't any.
		dns_event = dns_rejected;
	else
		dns_event = dns_query_reply;

	if ( dns_event && ! msg->skip_event )
		{
		BroString* question_name =
			new BroString(name, name_end - name, true);
		SendReplyOrRejectEvent(msg, dns_event, data, len, question_name);
		}
	else
		{
		// Consume the unused type/class.
		(void) ExtractShort(data, len);
		(void) ExtractShort(data, len);
		}

	return true;
	}

bool DNS_Interpreter::ParseAnswer(DNS_MsgInfo* msg,
				const u_char*& data, int& len,
				const u_char* msg_start)
	{
	u_char name[513];
	int name_len = sizeof(name) - 1;

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start);

	if ( ! name_end )
		return false;

	if ( len < int(sizeof(short)) * 2 )
		{
		analyzer->Weird("DNS_truncated_ans_too_short");
		return false;
		}

	// Note that the exact meaning of some of these fields will be
	// re-interpreted by other, more adventurous RR types.

	msg->query_name = make_intrusive<StringVal>(new BroString(name, name_end - name, true));
	msg->atype = RR_Type(ExtractShort(data, len));
	msg->aclass = ExtractShort(data, len);
	msg->ttl = ExtractLong(data, len);

	int rdlength = ExtractShort(data, len);
	if ( rdlength > len )
		{
		analyzer->Weird("DNS_truncated_RR_rdlength_lt_len");
		return false;
		}

	bool status;
	switch ( msg->atype ) {
		case TYPE_A:
			status = ParseRR_A(msg, data, len, rdlength);
			break;

		case TYPE_A6:
		case TYPE_AAAA:
			status = ParseRR_AAAA(msg, data, len, rdlength);
			break;

		case TYPE_NS:
		case TYPE_CNAME:
		case TYPE_PTR:
			status = ParseRR_Name(msg, data, len, rdlength, msg_start);
			break;

		case TYPE_SOA:
			status = ParseRR_SOA(msg, data, len, rdlength, msg_start);
			break;

		case TYPE_WKS:
			status = ParseRR_WKS(msg, data, len, rdlength);
			break;

		case TYPE_HINFO:
			status = ParseRR_HINFO(msg, data, len, rdlength);
			break;

		case TYPE_MX:
			status = ParseRR_MX(msg, data, len, rdlength, msg_start);
			break;

		case TYPE_TXT:
			status = ParseRR_TXT(msg, data, len, rdlength, msg_start);
			break;

		case TYPE_SPF:
			status = ParseRR_SPF(msg, data, len, rdlength, msg_start);
			break;

		case TYPE_CAA:
			status = ParseRR_CAA(msg, data, len, rdlength, msg_start);
			break;

		case TYPE_NBS:
			status = ParseRR_NBS(msg, data, len, rdlength, msg_start);
			break;

		case TYPE_SRV:
			if ( ntohs(analyzer->Conn()->RespPort()) == 137 )
				{
				// This is an NBSTAT (NetBIOS NODE STATUS) record.
				// The SRV RFC reused the value that was already being
				// used for this.
				// We aren't parsing this yet.
				status = true;
				}
			else
				status = ParseRR_SRV(msg, data, len, rdlength, msg_start);

			break;

		case TYPE_EDNS:
			status = ParseRR_EDNS(msg, data, len, rdlength, msg_start);
			break;

		case TYPE_TSIG:
			status = ParseRR_TSIG(msg, data, len, rdlength, msg_start);
			break;

		case TYPE_RRSIG:
			status = ParseRR_RRSIG(msg, data, len, rdlength, msg_start);
			break;

		case TYPE_DNSKEY:
			status = ParseRR_DNSKEY(msg, data, len, rdlength, msg_start);
			break;

		case TYPE_NSEC:
			status = ParseRR_NSEC(msg, data, len, rdlength, msg_start);
			break;

		case TYPE_NSEC3:
			status = ParseRR_NSEC3(msg, data, len, rdlength, msg_start);
			break;

		case TYPE_DS:
			status = ParseRR_DS(msg, data, len, rdlength, msg_start);
			break;

		default:

			if ( dns_unknown_reply && ! msg->skip_event )
				analyzer->EnqueueConnEvent(dns_unknown_reply,
					analyzer->ConnVal(),
					msg->BuildHdrVal(),
					msg->BuildAnswerVal()
				);

			analyzer->Weird("DNS_RR_unknown_type", fmt("%d", msg->atype));
			data += rdlength;
			len -= rdlength;
			status = true;
			break;
	}

	return status;
	}

u_char* DNS_Interpreter::ExtractName(const u_char*& data, int& len,
					u_char* name, int name_len,
					const u_char* msg_start)
	{
	u_char* name_start = name;

	while ( ExtractLabel(data, len, name, name_len, msg_start) )
		;

	int n = name - name_start;

	if ( n >= 255 )
		analyzer->Weird("DNS_NAME_too_long");

	if ( n >= 2 && name[-1] == '.' )
		{
		// Remove trailing dot.
		--name;
		name[0] = 0;
		}

	// Convert labels to lower case for consistency.
	for ( u_char* np = name_start; np < name; ++np )
		if ( isupper(*np) )
			*np = tolower(*np);

	return name;
	}

bool DNS_Interpreter::ExtractLabel(const u_char*& data, int& len,
				u_char*& name, int& name_len,
				const u_char* msg_start)
	{
	if ( len <= 0 )
		return false;

	const u_char* orig_data = data;
	int label_len = data[0];

	++data;
	--len;

	if ( len <= 0 )
		return false;

	if ( label_len == 0 )
		// Found terminating label.
		return false;

	if ( (label_len & 0xc0) == 0xc0 )
		{
		unsigned short offset = (label_len & ~0xc0) << 8;

		offset |= *data;

		++data;
		--len;

		if ( offset >= orig_data - msg_start )
			{
			// (You'd think that actually the offset should be
			//  at least 6 bytes below our current position:
			//  2 bytes for a non-trivial label, plus 4 bytes for
			//  its class and type, which presumably are between
			//  our current location and the instance of the label.
			//  But actually this turns out not to be the case -
			//  sometimes compression points to compression.)

			analyzer->Weird("DNS_label_forward_compress_offset");
			return false;
			}

		// Recursively resolve name.
		const u_char* recurse_data = msg_start + offset;
		int recurse_max_len = orig_data - recurse_data;

		u_char* name_end = ExtractName(recurse_data, recurse_max_len,
						name, name_len, msg_start);

		name_len -= name_end - name;
		name = name_end;

		return false;
		}

	if ( label_len > len )
		{
		analyzer->Weird("DNS_label_len_gt_pkt");
		data += len;	// consume the rest of the packet
		len = 0;
		return false;
		}

	if ( label_len > 63 &&
		// NetBIOS name service look ups can use longer labels.
		ntohs(analyzer->Conn()->RespPort()) != 137 )
		{
		analyzer->Weird("DNS_label_too_long");
		return false;
		}

	if ( label_len >= name_len )
		{
		analyzer->Weird("DNS_label_len_gt_name_len");
		return false;
		}

	memcpy(name, data, label_len);
	name[label_len] = '.';

	name += label_len + 1;
	name_len -= label_len + 1;

	data += label_len;
	len -= label_len;

	return true;
	}

uint16_t DNS_Interpreter::ExtractShort(const u_char*& data, int& len)
	{
	if ( len < 2 )
		return 0;

	uint16_t val;

	val = data[0] << 8;

	++data;
	--len;

	val |= data[0];

	++data;
	--len;

	return val;
	}

uint32_t DNS_Interpreter::ExtractLong(const u_char*& data, int& len)
	{
	if ( len < 4 )
		return 0;

	uint32_t val;

	val = data[0] << 24;
	val |= data[1] << 16;
	val |= data[2] << 8;
	val |= data[3];

	data += sizeof(val);
	len -= sizeof(val);

	return val;
	}

bool DNS_Interpreter::ParseRR_Name(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	const u_char* data_start = data;

	u_char name[513];
	int name_len = sizeof(name) - 1;

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start);
	if ( ! name_end )
		return false;

	if ( data - data_start != rdlength )
		{
		analyzer->Weird("DNS_RR_length_mismatch");
		}

	EventHandlerPtr reply_event;
	switch ( msg->atype ) {
		case TYPE_NS:
			reply_event = dns_NS_reply;
			break;

		case TYPE_CNAME:
		case TYPE_AAAA:
		case TYPE_A6:
			reply_event = dns_CNAME_reply;
			break;

		case TYPE_PTR:
			reply_event = dns_PTR_reply;
			break;

		default:
			analyzer->Conn()->Internal("DNS_RR_bad_name");
			reply_event = nullptr;
	}

	if ( reply_event && ! msg->skip_event )
		analyzer->EnqueueConnEvent(reply_event,
			analyzer->ConnVal(),
			msg->BuildHdrVal(),
			msg->BuildAnswerVal(),
			make_intrusive<StringVal>(new BroString(name, name_end - name, true))
		);

	return true;
	}

bool DNS_Interpreter::ParseRR_SOA(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	const u_char* data_start = data;

	u_char mname[513];
	int mname_len = sizeof(mname) - 1;

	u_char* mname_end = ExtractName(data, len, mname, mname_len, msg_start);
	if ( ! mname_end )
		return false;

	u_char rname[513];
	int rname_len = sizeof(rname) - 1;

	u_char* rname_end = ExtractName(data, len, rname, rname_len, msg_start);
	if ( ! rname_end )
		return false;

	if ( len < 20 )
		return false;

	uint32_t serial = ExtractLong(data, len);
	uint32_t refresh = ExtractLong(data, len);
	uint32_t retry = ExtractLong(data, len);
	uint32_t expire = ExtractLong(data, len);
	uint32_t minimum = ExtractLong(data, len);

	if ( data - data_start != rdlength )
		analyzer->Weird("DNS_RR_length_mismatch");

	if ( dns_SOA_reply && ! msg->skip_event )
		{
		static auto dns_soa = zeek::id::lookup_type<RecordType>("dns_soa");
		auto r = make_intrusive<RecordVal>(dns_soa);
		r->Assign(0, make_intrusive<StringVal>(new BroString(mname, mname_end - mname, true)));
		r->Assign(1, make_intrusive<StringVal>(new BroString(rname, rname_end - rname, true)));
		r->Assign(2, val_mgr->Count(serial));
		r->Assign(3, make_intrusive<IntervalVal>(double(refresh), Seconds));
		r->Assign(4, make_intrusive<IntervalVal>(double(retry), Seconds));
		r->Assign(5, make_intrusive<IntervalVal>(double(expire), Seconds));
		r->Assign(6, make_intrusive<IntervalVal>(double(minimum), Seconds));

		analyzer->EnqueueConnEvent(dns_SOA_reply,
			analyzer->ConnVal(),
			msg->BuildHdrVal(),
			msg->BuildAnswerVal(),
			std::move(r)
		);
		}

	return true;
	}

bool DNS_Interpreter::ParseRR_MX(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	const u_char* data_start = data;

	int preference = ExtractShort(data, len);

	u_char name[513];
	int name_len = sizeof(name) - 1;

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start);
	if ( ! name_end )
		return false;

	if ( data - data_start != rdlength )
		analyzer->Weird("DNS_RR_length_mismatch");

	if ( dns_MX_reply && ! msg->skip_event )
		analyzer->EnqueueConnEvent(dns_MX_reply,
			analyzer->ConnVal(),
			msg->BuildHdrVal(),
			msg->BuildAnswerVal(),
			make_intrusive<StringVal>(new BroString(name, name_end - name, true)),
			val_mgr->Count(preference)
		);

	return true;
	}

bool DNS_Interpreter::ParseRR_NBS(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	data += rdlength;
	len -= rdlength;
	return true;
	}

bool DNS_Interpreter::ParseRR_SRV(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	const u_char* data_start = data;

	unsigned int priority = ExtractShort(data, len);
	unsigned int weight = ExtractShort(data, len);
	unsigned int port = ExtractShort(data, len);

	u_char name[513];
	int name_len = sizeof(name) - 1;

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start);
	if ( ! name_end )
		return false;

	if ( data - data_start != rdlength )
		analyzer->Weird("DNS_RR_length_mismatch");

	if ( dns_SRV_reply && ! msg->skip_event )
		analyzer->EnqueueConnEvent(dns_SRV_reply,
			analyzer->ConnVal(),
			msg->BuildHdrVal(),
			msg->BuildAnswerVal(),
			make_intrusive<StringVal>(new BroString(name, name_end - name, true)),
			val_mgr->Count(priority),
			val_mgr->Count(weight),
			val_mgr->Count(port)
		);

	return true;
	}

bool DNS_Interpreter::ParseRR_EDNS(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	// We need a pair-value set mechanism here to dump useful information
	// out to the policy side of the house if rdlength > 0.

	if ( dns_EDNS_addl && ! msg->skip_event )
		analyzer->EnqueueConnEvent(dns_EDNS_addl,
			analyzer->ConnVal(),
			msg->BuildHdrVal(),
			msg->BuildEDNS_Val()
		);

	// Currently EDNS supports the movement of type:data pairs
	// in the RR_DATA section.  Here's where we should put together
	// a corresponding mechanism.
	if ( rdlength > 0 )
		{ // deal with data
		data += rdlength;
		len -= rdlength;
		}

	return true;
	}

void DNS_Interpreter::ExtractOctets(const u_char*& data, int& len,
                                    BroString** p)
	{
	uint16_t dlen = ExtractShort(data, len);
	dlen = min(len, static_cast<int>(dlen));

	if ( p )
		*p = new BroString(data, dlen, false);

	data += dlen;
	len -= dlen;
	}

BroString* DNS_Interpreter::ExtractStream(const u_char*& data, int& len, int l)
	{
	l = max(l, 0);
	int dlen = min(len, l); // Len in bytes of the algorithm use
	auto rval = new BroString(data, dlen, false);

	data += dlen;
	len -= dlen;
	return rval;
	}

bool DNS_Interpreter::ParseRR_TSIG(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	const u_char* data_start = data;
	u_char alg_name[1024];
	int alg_name_len = sizeof(alg_name) - 1;

	u_char* alg_name_end =
		ExtractName(data, len, alg_name, alg_name_len, msg_start);

	if ( ! alg_name_end )
		return false;

	uint32_t sign_time_sec = ExtractLong(data, len);
	unsigned int sign_time_msec = ExtractShort(data, len);
	unsigned int fudge = ExtractShort(data, len);
	BroString* request_MAC;
	ExtractOctets(data, len, dns_TSIG_addl ? &request_MAC : nullptr);
	unsigned int orig_id = ExtractShort(data, len);
	unsigned int rr_error = ExtractShort(data, len);
	ExtractOctets(data, len, nullptr);  // Other Data

	if ( dns_TSIG_addl )
		{
		TSIG_DATA tsig;
		tsig.alg_name =
			new BroString(alg_name, alg_name_end - alg_name, true);
		tsig.sig = request_MAC;
		tsig.time_s = sign_time_sec;
		tsig.time_ms = sign_time_msec;
		tsig.fudge = fudge;
		tsig.orig_id = orig_id;
		tsig.rr_error = rr_error;

		analyzer->EnqueueConnEvent(dns_TSIG_addl,
			analyzer->ConnVal(),
			msg->BuildHdrVal(),
			msg->BuildTSIG_Val(&tsig)
		);
		}

	return true;
	}

bool DNS_Interpreter::ParseRR_RRSIG(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	if ( ! dns_RRSIG || msg->skip_event )
		{
		data += rdlength;
		len -= rdlength;
		return true;
		}

	if ( len < 18 )
		return false;

	unsigned int type_covered = ExtractShort(data, len);
	// split the two bytes for algo and labels extraction
	uint32_t algo_lab = ExtractShort(data, len);
	unsigned int algo = (algo_lab >> 8) & 0xff;
	unsigned int lab = algo_lab & 0xff;

	uint32_t orig_ttl = ExtractLong(data, len);
	uint32_t sign_exp = ExtractLong(data, len);
	uint32_t sign_incp = ExtractLong(data, len);
	unsigned int key_tag = ExtractShort(data, len);

	//implement signer's name with the msg_start offset
	const u_char* data_start = data;
	u_char name[513];
	int name_len = sizeof(name) - 1;

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start);
	if ( ! name_end )
		return false;

	int sig_len = rdlength - ((data - data_start) + 18);
	DNSSEC_Algo dsa = DNSSEC_Algo(algo);
	BroString* sign = ExtractStream(data, len, sig_len);

	switch ( dsa ) {
		case RSA_MD5:
			analyzer->Weird("DNSSEC_RRSIG_NotRecommended_ZoneSignAlgo", fmt("%d", algo));
			break;
		case Diffie_Hellman:
			break;
		case DSA_SHA1:
			break;
		case Elliptic_Curve:
			break;
		case RSA_SHA1:
			break;
		case DSA_NSEC3_SHA1:
			break;
		case RSA_SHA1_NSEC3_SHA1:
			break;
		case RSA_SHA256:
			break;
		case RSA_SHA512:
			break;
		case GOST_R_34_10_2001:
			break;
		case ECDSA_curveP256withSHA256:
			break;
		case ECDSA_curveP384withSHA384:
			break;
		case Indirect:
			analyzer->Weird("DNSSEC_RRSIG_Indirect_ZoneSignAlgo", fmt("%d", algo));
			break;
		case PrivateDNS:
			analyzer->Weird("DNSSEC_RRSIG_PrivateDNS_ZoneSignAlgo", fmt("%d", algo));
			break;
		case PrivateOID:
			analyzer->Weird("DNSSEC_RRSIG_PrivateOID_ZoneSignAlgo", fmt("%d", algo));
			break;
		default:
			analyzer->Weird("DNSSEC_RRSIG_unknown_ZoneSignAlgo", fmt("%d", algo));
			break;
	}

	if ( dns_RRSIG )
		{
		RRSIG_DATA rrsig;
		rrsig.type_covered = type_covered;
		rrsig.algorithm = algo;
		rrsig.labels = lab;
		rrsig.orig_ttl = orig_ttl;
		rrsig.sig_exp = sign_exp;
		rrsig.sig_incep = sign_incp;
		rrsig.key_tag = key_tag;
		rrsig.signer_name = new BroString(name, name_end - name, true);
		rrsig.signature = sign;

		analyzer->EnqueueConnEvent(dns_RRSIG,
			analyzer->ConnVal(),
			msg->BuildHdrVal(),
			msg->BuildAnswerVal(),
			msg->BuildRRSIG_Val(&rrsig)
		);
		}

	return true;
	}

bool DNS_Interpreter::ParseRR_DNSKEY(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	if ( ! dns_DNSKEY || msg->skip_event )
		{
		data += rdlength;
		len -= rdlength;
		return true;
		}

	if ( len < 4 )
		return false;

	auto dflags = ExtractShort(data, len);
	// split the two bytes for protocol and algorithm extraction
	auto proto_algo = ExtractShort(data, len);
	unsigned int dprotocol = (proto_algo >> 8) & 0xff;
	unsigned int dalgorithm = proto_algo & 0xff;
	DNSSEC_Algo dsa = DNSSEC_Algo(dalgorithm);
	//Evaluating the size of remaining bytes for Public Key
	BroString* key = ExtractStream(data, len, rdlength - 4);

	// flags bit  7: zone key
	// flags bit  8: revoked
	// flags bit 15: Secure Entry Point, key signing key
	if ( (dflags & 0xfe7e) != 0 )
		analyzer->Weird("DNSSEC_DNSKEY_Invalid_Flag", fmt("%d", dflags));

	// flags bit 7, 8, and 15 all set
	if ( (dflags & 0x0181) == 0x0181 )
		analyzer->Weird("DNSSEC_DNSKEY_Revoked_KSK", fmt("%d", dflags));

	if ( dprotocol != 3 )
		analyzer->Weird("DNSSEC_DNSKEY_Invalid_Protocol", fmt("%d", dprotocol));

	switch ( dsa ) {
		case RSA_MD5:
			analyzer->Weird("DNSSEC_DNSKEY_NotRecommended_ZoneSignAlgo", fmt("%d", dalgorithm));
			break;
		case Diffie_Hellman:
			break;
		case DSA_SHA1:
			break;
		case Elliptic_Curve:
			break;
		case RSA_SHA1:
			break;
		case DSA_NSEC3_SHA1:
			break;
		case RSA_SHA1_NSEC3_SHA1:
			break;
		case RSA_SHA256:
			break;
		case RSA_SHA512:
			break;
		case GOST_R_34_10_2001:
			break;
		case ECDSA_curveP256withSHA256:
			break;
		case ECDSA_curveP384withSHA384:
			break;
		case Indirect:
			analyzer->Weird("DNSSEC_DNSKEY_Indirect_ZoneSignAlgo", fmt("%d", dalgorithm));
			break;
		case PrivateDNS:
			analyzer->Weird("DNSSEC_DNSKEY_PrivateDNS_ZoneSignAlgo", fmt("%d", dalgorithm));
			break;
		case PrivateOID:
			analyzer->Weird("DNSSEC_DNSKEY_PrivateOID_ZoneSignAlgo", fmt("%d", dalgorithm));
			break;
		default:
			analyzer->Weird("DNSSEC_DNSKEY_unknown_ZoneSignAlgo", fmt("%d", dalgorithm));
			break;
	}

	if ( dns_DNSKEY )
		{
		DNSKEY_DATA dnskey;
		dnskey.dflags = dflags;
		dnskey.dalgorithm = dalgorithm;
		dnskey.dprotocol = dprotocol;
		dnskey.public_key = key;

		analyzer->EnqueueConnEvent(dns_DNSKEY,
			analyzer->ConnVal(),
			msg->BuildHdrVal(),
			msg->BuildAnswerVal(),
			msg->BuildDNSKEY_Val(&dnskey)
		);
		}

	return true;
	}

bool DNS_Interpreter::ParseRR_NSEC(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	if ( ! dns_NSEC || msg->skip_event )
		{
		data += rdlength;
		len -= rdlength;
		return true;
		}

	const u_char* data_start = data;
	u_char name[513];
	int name_len = sizeof(name) - 1;

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start);
	if ( ! name_end )
		return false;

	int typebitmaps_len = rdlength - (data - data_start);

	auto char_strings = make_intrusive<VectorVal>(zeek::id::string_vec);

	while ( typebitmaps_len > 0 && len > 0 )
		{
		uint32_t block_bmlen = ExtractShort(data, len);
		unsigned int win_blck = (block_bmlen >> 8) & 0xff;
		unsigned int bmlen = block_bmlen & 0xff;

		if ( bmlen == 0 )
			{
			analyzer->Weird("DNSSEC_NSEC_bitmapLen0", fmt("%d", win_blck));
			break;
			}

		BroString* bitmap = ExtractStream(data, len, bmlen);
		char_strings->Assign(char_strings->Size(), make_intrusive<StringVal>(bitmap));
		typebitmaps_len = typebitmaps_len - (2 + bmlen);
		}

	if ( dns_NSEC )
		analyzer->EnqueueConnEvent(dns_NSEC,
			analyzer->ConnVal(),
			msg->BuildHdrVal(),
			msg->BuildAnswerVal(),
			make_intrusive<StringVal>(new BroString(name, name_end - name, true)),
			std::move(char_strings)
		);

	return true;
	}

bool DNS_Interpreter::ParseRR_NSEC3(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	if ( ! dns_NSEC3 || msg->skip_event )
		{
		data += rdlength;
		len -= rdlength;
		return true;
		}

	if ( len < 6 )
		return false;

	const u_char* data_start = data;
	uint32_t halgo_flags = ExtractShort(data, len);
	unsigned int hash_algo = (halgo_flags >> 8) & 0xff;
	unsigned int nsec_flags = halgo_flags & 0xff;
	unsigned int iter = ExtractShort(data, len);

	uint8_t salt_len = 0;

	if ( len > 0 )
		{
		salt_len = data[0];
		++data;
		--len;
		}

	auto salt_val = ExtractStream(data, len, static_cast<int>(salt_len));

	uint8_t hash_len = 0;

	if ( len > 0 )
		{
		hash_len = data[0];
		++data;
		--len;
		}

	auto hash_val = ExtractStream(data, len, static_cast<int>(hash_len));

	int typebitmaps_len = rdlength - (data - data_start);

	auto char_strings = make_intrusive<VectorVal>(zeek::id::string_vec);

	while ( typebitmaps_len > 0 && len > 0 )
		{
		uint32_t block_bmlen = ExtractShort(data, len);
		unsigned int win_blck = ( block_bmlen >> 8) & 0xff;
		unsigned int bmlen = block_bmlen & 0xff;

		if ( bmlen == 0 )
			{
			analyzer->Weird("DNSSEC_NSEC3_bitmapLen0", fmt("%d", win_blck));
			break;
			}

		BroString* bitmap = ExtractStream(data, len, bmlen);
		char_strings->Assign(char_strings->Size(), make_intrusive<StringVal>(bitmap));
		typebitmaps_len = typebitmaps_len - (2 + bmlen);
		}

	if ( dns_NSEC3 )
		{
		NSEC3_DATA nsec3;
		nsec3.nsec_flags = nsec_flags;
		nsec3.nsec_hash_algo = hash_algo;
		nsec3.nsec_iter = iter;
		nsec3.nsec_salt_len = salt_len;
		nsec3.nsec_salt = salt_val;
		nsec3.nsec_hlen = hash_len;
		nsec3.nsec_hash = hash_val;
		nsec3.bitmaps = std::move(char_strings);

		analyzer->EnqueueConnEvent(dns_NSEC3,
			analyzer->ConnVal(),
			msg->BuildHdrVal(),
			msg->BuildAnswerVal(),
			msg->BuildNSEC3_Val(&nsec3)
		);
		}

	return true;
	}

bool DNS_Interpreter::ParseRR_DS(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	if ( ! dns_DS || msg->skip_event )
		{
		data += rdlength;
		len -= rdlength;
		return true;
		}

	if ( len < 4 )
		return false;

	unsigned int ds_key_tag = ExtractShort(data, len);
	// split the two bytes for algorithm and digest type extraction
	uint32_t ds_algo_dtype = ExtractShort(data, len);
	unsigned int ds_algo = (ds_algo_dtype >> 8) & 0xff;
	unsigned int ds_dtype = ds_algo_dtype & 0xff;
	DNSSEC_Digest ds_digest_type = DNSSEC_Digest(ds_dtype);
	BroString* ds_digest = ExtractStream(data, len, rdlength - 4);

	switch ( ds_digest_type ) {
		case SHA1:
			break;
		case SHA256:
			break;
		case GOST_R_34_11_94:
			break;
		case SHA384:
			break;
		case analyzer::dns::reserved:
			analyzer->Weird("DNSSEC_DS_ResrevedDigestType", fmt("%d", ds_dtype));
			break;
		default:
			analyzer->Weird("DNSSEC_DS_unknown_DigestType", fmt("%d", ds_dtype));
			break;
	}

	if ( dns_DS )
		{
		DS_DATA ds;
		ds.key_tag = ds_key_tag;
		ds.algorithm = ds_algo;
		ds.digest_type = ds_dtype;
		ds.digest_val = ds_digest;

		analyzer->EnqueueConnEvent(dns_DS,
			analyzer->ConnVal(),
			msg->BuildHdrVal(),
			msg->BuildAnswerVal(),
			msg->BuildDS_Val(&ds)
		);
		}

	return true;
	}

bool DNS_Interpreter::ParseRR_A(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength)
	{
	if ( rdlength != 4 )
		{
		analyzer->Weird("DNS_RR_bad_length");
		return false;
		}

	uint32_t addr = ExtractLong(data, len);

	if ( dns_A_reply && ! msg->skip_event )
		analyzer->EnqueueConnEvent(dns_A_reply,
			analyzer->ConnVal(),
			msg->BuildHdrVal(),
			msg->BuildAnswerVal(),
			make_intrusive<AddrVal>(htonl(addr))
		);

	return true;
	}

bool DNS_Interpreter::ParseRR_AAAA(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength)
	{
	uint32_t addr[4];

	for ( int i = 0; i < 4; ++i )
		{
		addr[i] = htonl(ExtractLong(data, len));

		if ( len < 0 )
			{
			if ( msg->atype == TYPE_AAAA )
				analyzer->Weird("DNS_AAAA_neg_length");
			else
				analyzer->Weird("DNS_A6_neg_length");
			return false;
			}
		}

	EventHandlerPtr event;
	if ( msg->atype == TYPE_AAAA )
		event = dns_AAAA_reply;
	else
		event = dns_A6_reply;

	if ( event && ! msg->skip_event )
		analyzer->EnqueueConnEvent(event,
			analyzer->ConnVal(),
			msg->BuildHdrVal(),
			msg->BuildAnswerVal(),
			make_intrusive<AddrVal>(addr)
		);

	return true;
	}

bool DNS_Interpreter::ParseRR_WKS(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength)
	{
	data += rdlength;
	len -= rdlength;

	return true;
	}

bool DNS_Interpreter::ParseRR_HINFO(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength)
	{
	data += rdlength;
	len -= rdlength;

	return true;
	}

static IntrusivePtr<StringVal>
extract_char_string(analyzer::Analyzer* analyzer,
                    const u_char*& data, int& len, int& rdlen)
	{
	if ( rdlen <= 0 )
		return nullptr;

	uint8_t str_size = data[0];

	--rdlen;
	--len;
	++data;

	if ( str_size > rdlen )
		{
		analyzer->Weird("DNS_TXT_char_str_past_rdlen");
		return nullptr;
		}

	auto rval = make_intrusive<StringVal>(str_size, reinterpret_cast<const char*>(data));

	rdlen -= str_size;
	len -= str_size;
	data += str_size;

	return rval;
	}

bool DNS_Interpreter::ParseRR_TXT(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	if ( ! dns_TXT_reply || msg->skip_event )
		{
		data += rdlength;
		len -= rdlength;
		return true;
		}

	auto char_strings = make_intrusive<VectorVal>(zeek::id::string_vec);
	IntrusivePtr<StringVal> char_string;

	while ( (char_string = extract_char_string(analyzer, data, len, rdlength)) )
		char_strings->Assign(char_strings->Size(), std::move(char_string));

	if ( dns_TXT_reply )
		analyzer->EnqueueConnEvent(dns_TXT_reply,
			analyzer->ConnVal(),
			msg->BuildHdrVal(),
			msg->BuildAnswerVal(),
			std::move(char_strings)
		);

	return rdlength == 0;
	}

bool DNS_Interpreter::ParseRR_SPF(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	if ( ! dns_SPF_reply || msg->skip_event )
		{
		data += rdlength;
		len -= rdlength;
		return true;
		}

	auto char_strings = make_intrusive<VectorVal>(zeek::id::string_vec);
	IntrusivePtr<StringVal> char_string;

	while ( (char_string = extract_char_string(analyzer, data, len, rdlength)) )
		char_strings->Assign(char_strings->Size(), std::move(char_string));

	if ( dns_SPF_reply )
		analyzer->EnqueueConnEvent(dns_SPF_reply,
			analyzer->ConnVal(),
			msg->BuildHdrVal(),
			msg->BuildAnswerVal(),
			std::move(char_strings)
		);

	return rdlength == 0;
	}

bool DNS_Interpreter::ParseRR_CAA(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	if ( ! dns_CAA_reply || msg->skip_event )
		{
		data += rdlength;
		len -= rdlength;
		return true;
		}

	unsigned int flags = ExtractShort(data, len);
	unsigned int tagLen = flags & 0xff;
	flags = flags >> 8;
	rdlength -= 2;
	if ( (int) tagLen >= rdlength )
		{
		analyzer->Weird("DNS_CAA_char_str_past_rdlen");
		return false;
		}
	BroString* tag = new BroString(data, tagLen, true);
	len -= tagLen;
	data += tagLen;
	rdlength -= tagLen;
	BroString* value = new BroString(data, rdlength, false);

	len -= value->Len();
	data += value->Len();
	rdlength -= value->Len();

	if ( dns_CAA_reply )
		analyzer->EnqueueConnEvent(dns_CAA_reply,
			analyzer->ConnVal(),
			msg->BuildHdrVal(),
			msg->BuildAnswerVal(),
			val_mgr->Count(flags),
			make_intrusive<StringVal>(tag),
			make_intrusive<StringVal>(value)
		);
	else
		{
		delete tag;
		delete value;
		}

	return rdlength == 0;
	}


void DNS_Interpreter::SendReplyOrRejectEvent(DNS_MsgInfo* msg,
						EventHandlerPtr event,
						const u_char*& data, int& len,
						BroString* question_name)
	{
	RR_Type qtype = RR_Type(ExtractShort(data, len));
	int qclass = ExtractShort(data, len);

	assert(event);

	analyzer->EnqueueConnEvent(event,
		analyzer->ConnVal(),
		msg->BuildHdrVal(),
		make_intrusive<StringVal>(question_name),
		val_mgr->Count(qtype),
		val_mgr->Count(qclass)
	);
	}


DNS_MsgInfo::DNS_MsgInfo(DNS_RawMsgHdr* hdr, int arg_is_query)
	{
	//### Need to fix alignment if hdr is misaligned (not on a short
	// boundary).
	unsigned short flags = ntohs(hdr->flags);

	QR = (flags & 0x8000) != 0;
	opcode = (flags & 0x7800) >> 11;
	AA = (flags & 0x0400) != 0;
	TC = (flags & 0x0200) != 0;
	RD = (flags & 0x0100) != 0;
	RA = (flags & 0x0080) != 0;
	Z = (flags & 0x0070) >> 4;
	rcode = (flags & 0x000f);

	qdcount = ntohs(hdr->qdcount);
	ancount = ntohs(hdr->ancount);
	nscount = ntohs(hdr->nscount);
	arcount = ntohs(hdr->arcount);

	id = ntohs(hdr->id);
	is_query = arg_is_query;

	atype = TYPE_ALL;
	aclass = 0;
	ttl = 0;

	answer_type = DNS_QUESTION;
	skip_event = 0;
	}

IntrusivePtr<RecordVal> DNS_MsgInfo::BuildHdrVal()
	{
	static auto dns_msg = zeek::id::lookup_type<RecordType>("dns_msg");
	auto r = make_intrusive<RecordVal>(dns_msg);

	r->Assign(0, val_mgr->Count(id));
	r->Assign(1, val_mgr->Count(opcode));
	r->Assign(2, val_mgr->Count(rcode));
	r->Assign(3, val_mgr->Bool(QR));
	r->Assign(4, val_mgr->Bool(AA));
	r->Assign(5, val_mgr->Bool(TC));
	r->Assign(6, val_mgr->Bool(RD));
	r->Assign(7, val_mgr->Bool(RA));
	r->Assign(8, val_mgr->Count(Z));
	r->Assign(9, val_mgr->Count(qdcount));
	r->Assign(10, val_mgr->Count(ancount));
	r->Assign(11, val_mgr->Count(nscount));
	r->Assign(12, val_mgr->Count(arcount));

	return r;
	}

IntrusivePtr<RecordVal> DNS_MsgInfo::BuildAnswerVal()
	{
	static auto dns_answer = zeek::id::lookup_type<RecordType>("dns_answer");
	auto r = make_intrusive<RecordVal>(dns_answer);

	r->Assign(0, val_mgr->Count(int(answer_type)));
	r->Assign(1, query_name);
	r->Assign(2, val_mgr->Count(atype));
	r->Assign(3, val_mgr->Count(aclass));
	r->Assign(4, make_intrusive<IntervalVal>(double(ttl), Seconds));

	return r;
	}

IntrusivePtr<RecordVal> DNS_MsgInfo::BuildEDNS_Val()
	{
	// We have to treat the additional record type in EDNS differently
	// than a regular resource record.
	static auto dns_edns_additional = zeek::id::lookup_type<RecordType>("dns_edns_additional");
	auto r = make_intrusive<RecordVal>(dns_edns_additional);

	r->Assign(0, val_mgr->Count(int(answer_type)));
	r->Assign(1, query_name);

	// type = 0x29 or 41 = EDNS
	r->Assign(2, val_mgr->Count(atype));

	// sender's UDP payload size, per RFC 2671 4.3
	r->Assign(3, val_mgr->Count(aclass));

	// Need to break the TTL field into three components:
	// initial: [------------- ttl (32) ---------------------]
	// after:   [ ext rcode (8)][ver # (8)][   Z field (16)  ]

	unsigned int ercode = (ttl >> 24) & 0xff;
	unsigned int version = (ttl >> 16) & 0xff;
	// unsigned int DO = ttl & 0x8000;	// "DNSSEC OK" - RFC 3225
	unsigned int z = ttl & 0xffff;

	unsigned int return_error = (ercode << 8) | rcode;

	r->Assign(4, val_mgr->Count(return_error));
	r->Assign(5, val_mgr->Count(version));
	r->Assign(6, val_mgr->Count(z));
	r->Assign(7, make_intrusive<IntervalVal>(double(ttl), Seconds));
	r->Assign(8, val_mgr->Count(is_query));

	return r;
	}

IntrusivePtr<RecordVal> DNS_MsgInfo::BuildTSIG_Val(struct TSIG_DATA* tsig)
	{
	static auto dns_tsig_additional = zeek::id::lookup_type<RecordType>("dns_tsig_additional");
	auto r = make_intrusive<RecordVal>(dns_tsig_additional);
	double rtime = tsig->time_s + tsig->time_ms / 1000.0;

	// r->Assign(0, val_mgr->Count(int(answer_type)));
	r->Assign(0, query_name);
	r->Assign(1, val_mgr->Count(int(answer_type)));
	r->Assign(2, make_intrusive<StringVal>(tsig->alg_name));
	r->Assign(3, make_intrusive<StringVal>(tsig->sig));
	r->Assign(4, make_intrusive<Val>(rtime, TYPE_TIME));
	r->Assign(5, make_intrusive<Val>(double(tsig->fudge), TYPE_TIME));
	r->Assign(6, val_mgr->Count(tsig->orig_id));
	r->Assign(7, val_mgr->Count(tsig->rr_error));
	r->Assign(8, val_mgr->Count(is_query));

	return r;
	}

IntrusivePtr<RecordVal> DNS_MsgInfo::BuildRRSIG_Val(RRSIG_DATA* rrsig)
	{
	static auto dns_rrsig_rr = zeek::id::lookup_type<RecordType>("dns_rrsig_rr");
	auto r = make_intrusive<RecordVal>(dns_rrsig_rr);

	r->Assign(0, query_name);
	r->Assign(1, val_mgr->Count(int(answer_type)));
	r->Assign(2, val_mgr->Count(rrsig->type_covered));
	r->Assign(3, val_mgr->Count(rrsig->algorithm));
	r->Assign(4, val_mgr->Count(rrsig->labels));
	r->Assign(5, make_intrusive<IntervalVal>(double(rrsig->orig_ttl), Seconds));
	r->Assign(6, make_intrusive<Val>(double(rrsig->sig_exp), TYPE_TIME));
	r->Assign(7, make_intrusive<Val>(double(rrsig->sig_incep), TYPE_TIME));
	r->Assign(8, val_mgr->Count(rrsig->key_tag));
	r->Assign(9, make_intrusive<StringVal>(rrsig->signer_name));
	r->Assign(10, make_intrusive<StringVal>(rrsig->signature));
	r->Assign(11, val_mgr->Count(is_query));

	return r;
	}

IntrusivePtr<RecordVal> DNS_MsgInfo::BuildDNSKEY_Val(DNSKEY_DATA* dnskey)
	{
	static auto dns_dnskey_rr = zeek::id::lookup_type<RecordType>("dns_dnskey_rr");
	auto r = make_intrusive<RecordVal>(dns_dnskey_rr);

	r->Assign(0, query_name);
	r->Assign(1, val_mgr->Count(int(answer_type)));
	r->Assign(2, val_mgr->Count(dnskey->dflags));
	r->Assign(3, val_mgr->Count(dnskey->dprotocol));
	r->Assign(4, val_mgr->Count(dnskey->dalgorithm));
	r->Assign(5, make_intrusive<StringVal>(dnskey->public_key));
	r->Assign(6, val_mgr->Count(is_query));

	return r;
	}

IntrusivePtr<RecordVal> DNS_MsgInfo::BuildNSEC3_Val(NSEC3_DATA* nsec3)
	{
	static auto dns_nsec3_rr = zeek::id::lookup_type<RecordType>("dns_nsec3_rr");
	auto r = make_intrusive<RecordVal>(dns_nsec3_rr);

	r->Assign(0, query_name);
	r->Assign(1, val_mgr->Count(int(answer_type)));
	r->Assign(2, val_mgr->Count(nsec3->nsec_flags));
	r->Assign(3, val_mgr->Count(nsec3->nsec_hash_algo));
	r->Assign(4, val_mgr->Count(nsec3->nsec_iter));
	r->Assign(5, val_mgr->Count(nsec3->nsec_salt_len));
	r->Assign(6, make_intrusive<StringVal>(nsec3->nsec_salt));
	r->Assign(7, val_mgr->Count(nsec3->nsec_hlen));
	r->Assign(8, make_intrusive<StringVal>(nsec3->nsec_hash));
	r->Assign(9, std::move(nsec3->bitmaps));
	r->Assign(10, val_mgr->Count(is_query));

	return r;
	}

IntrusivePtr<RecordVal> DNS_MsgInfo::BuildDS_Val(DS_DATA* ds)
	{
	static auto dns_ds_rr = zeek::id::lookup_type<RecordType>("dns_ds_rr");
	auto r = make_intrusive<RecordVal>(dns_ds_rr);

	r->Assign(0, query_name);
	r->Assign(1, val_mgr->Count(int(answer_type)));
	r->Assign(2, val_mgr->Count(ds->key_tag));
	r->Assign(3, val_mgr->Count(ds->algorithm));
	r->Assign(4, val_mgr->Count(ds->digest_type));
	r->Assign(5, make_intrusive<StringVal>(ds->digest_val));
	r->Assign(6, val_mgr->Count(is_query));

	return r;
	}

Contents_DNS::Contents_DNS(Connection* conn, bool orig,
				DNS_Interpreter* arg_interp)
: tcp::TCP_SupportAnalyzer("CONTENTS_DNS", conn, orig)
	{
	interp = arg_interp;

	msg_buf = nullptr;
	buf_n = buf_len = msg_size = 0;
	state = DNS_LEN_HI;
	}

Contents_DNS::~Contents_DNS()
	{
	free(msg_buf);
	}

void Contents_DNS::Flush()
	{
	if ( buf_n > 0 )
		{ // Deliver partial message.
		// '2' here means whether it's a query is unknown.
		interp->ParseMessage(msg_buf, buf_n, 2);
		msg_size = 0;
		}
	}

void Contents_DNS::DeliverStream(int len, const u_char* data, bool orig)
	{
	if ( state == DNS_LEN_HI )
		{
		msg_size = (*data) << 8;
		state = DNS_LEN_LO;

		++data;
		--len;

		if ( len == 0 )
			return;
		}

	if ( state == DNS_LEN_LO )
		{
		msg_size += *data;
		state = DNS_MESSAGE_BUFFER;

		buf_n = 0;

		if ( msg_buf )
			{
			if ( buf_len < msg_size )
				{
				buf_len = msg_size;
				msg_buf = (u_char*) safe_realloc((void*) msg_buf, buf_len);
				}
			}
		else
			{
			buf_len = msg_size;
			msg_buf = (u_char*) safe_malloc(buf_len);
			}

		++data;
		--len;

		if ( len == 0 )
			return;
		}

	if ( state != DNS_MESSAGE_BUFFER )
		Conn()->Internal("state inconsistency in Contents_DNS::DeliverStream");

	int n;
	for ( n = 0; buf_n < msg_size && n < len; ++n )
		msg_buf[buf_n++] = data[n];

	if ( buf_n < msg_size )
		// Haven't filled up the message buffer yet, no more to do.
		return;

	ForwardPacket(msg_size, msg_buf, orig, -1, nullptr, 0);

	buf_n = 0;
	state = DNS_LEN_HI;

	if ( n < len )
		// More data to munch on.
		DeliverStream(len - n, data + n, orig);
	}

DNS_Analyzer::DNS_Analyzer(Connection* conn)
: tcp::TCP_ApplicationAnalyzer("DNS", conn)
	{
	interp = new DNS_Interpreter(this);
	contents_dns_orig = contents_dns_resp = nullptr;

	if ( Conn()->ConnTransport() == TRANSPORT_TCP )
		{
		contents_dns_orig = new Contents_DNS(conn, true, interp);
		contents_dns_resp = new Contents_DNS(conn, false, interp);
		AddSupportAnalyzer(contents_dns_orig);
		AddSupportAnalyzer(contents_dns_resp);
		}
	else
		{
		ADD_ANALYZER_TIMER(&DNS_Analyzer::ExpireTimer,
					network_time + dns_session_timeout, true,
					TIMER_DNS_EXPIRE);
		}
	}

DNS_Analyzer::~DNS_Analyzer()
	{
	delete interp;
	}

void DNS_Analyzer::Init()
	{
	}

void DNS_Analyzer::Done()
	{
	tcp::TCP_ApplicationAnalyzer::Done();

	if ( Conn()->ConnTransport() == TRANSPORT_UDP )
		Event(udp_session_done);
	else
		interp->Timeout();
	}

void DNS_Analyzer::DeliverPacket(int len, const u_char* data, bool orig,
					uint64_t seq, const IP_Hdr* ip, int caplen)
	{
	tcp::TCP_ApplicationAnalyzer::DeliverPacket(len, data, orig, seq, ip, caplen);
	interp->ParseMessage(data, len, orig ? 1 : 0);
	}


void DNS_Analyzer::ConnectionClosed(tcp::TCP_Endpoint* endpoint, tcp::TCP_Endpoint* peer,
					bool gen_event)
	{
	tcp::TCP_ApplicationAnalyzer::ConnectionClosed(endpoint, peer, gen_event);

	assert(contents_dns_orig && contents_dns_resp);
	contents_dns_orig->Flush();
	contents_dns_resp->Flush();
	}

void DNS_Analyzer::ExpireTimer(double t)
	{
	// The - 1.0 in the following is to allow 1 second for the
	// common case of a single request followed by a single reply,
	// so we don't needlessly set the timer twice in that case.
	if ( t - Conn()->LastTime() >= dns_session_timeout - 1.0 || terminating )
		{
		Event(connection_timeout);
		sessions->Remove(Conn());
		}
	else
		ADD_ANALYZER_TIMER(&DNS_Analyzer::ExpireTimer,
				t + dns_session_timeout, true, TIMER_DNS_EXPIRE);
	}
