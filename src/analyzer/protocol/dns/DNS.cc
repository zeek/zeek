// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "NetVar.h"
#include "DNS.h"
#include "Sessions.h"
#include "Event.h"

#include "events.bif.h"

using namespace analyzer::dns;

DNS_Interpreter::DNS_Interpreter(analyzer::Analyzer* arg_analyzer)
	{
	analyzer = arg_analyzer;
	}

int DNS_Interpreter::ParseMessage(const u_char* data, int len, int is_query)
	{
	int hdr_len = sizeof(DNS_RawMsgHdr);

	if ( len < hdr_len )
		{
		analyzer->Weird("DNS_truncated_len_lt_hdr_len");
		return 0;
		}

	DNS_MsgInfo msg((DNS_RawMsgHdr*) data, is_query);

	if ( dns_message )
		{
		val_list* vl = new val_list();
		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(is_query, TYPE_BOOL));
		vl->append(msg.BuildHdrVal());
		vl->append(new Val(len, TYPE_COUNT));

		analyzer->ConnectionEvent(dns_message, vl);
		}

	// There is a great deal of non-DNS traffic that runs on port 53.
	// This should weed out most of it.
	if ( dns_max_queries > 0 && msg.qdcount > dns_max_queries )
		{
		analyzer->ProtocolViolation("DNS_Conn_count_too_large");
		analyzer->Weird("DNS_Conn_count_too_large");
		EndMessage(&msg);
		return 0;
		}

	const u_char* msg_start = data;	// needed for interpreting compression

	data += hdr_len;
	len -= hdr_len;

	if ( ! ParseQuestions(&msg, data, len, msg_start) )
		{
		EndMessage(&msg);
		return 0;
		}

	if ( ! ParseAnswers(&msg, msg.ancount, DNS_ANSWER,
				data, len, msg_start) )
		{
		EndMessage(&msg);
		return 0;
		}

	analyzer->ProtocolConfirmation();

	AddrVal server(analyzer->Conn()->RespAddr());

	int skip_auth = dns_skip_all_auth;
	int skip_addl = dns_skip_all_addl;
	if ( msg.ancount > 0 )
		{ // We did an answer, so can potentially skip auth/addl.
		skip_auth = skip_auth || msg.nscount == 0 ||
				dns_skip_auth->Lookup(&server);
		skip_addl = skip_addl || msg.arcount == 0 ||
				dns_skip_addl->Lookup(&server);
		}

	if ( skip_auth && skip_addl )
		{
		// No point doing further work parsing the message.
		EndMessage(&msg);
		return 1;
		}

	msg.skip_event = skip_auth;
	if ( ! ParseAnswers(&msg, msg.nscount, DNS_AUTHORITY,
				data, len, msg_start) )
		{
		EndMessage(&msg);
		return 0;
		}

	if ( skip_addl )
		{
		// No point doing further work parsing the message.
		EndMessage(&msg);
		return 1;
		}

	msg.skip_event = skip_addl;
	if ( ! ParseAnswers(&msg, msg.arcount, DNS_ADDITIONAL,
				data, len, msg_start) )
		{
		EndMessage(&msg);
		return 0;
		}

	EndMessage(&msg);
	return 1;
	}

int DNS_Interpreter::EndMessage(DNS_MsgInfo* msg)
	{
	val_list* vl = new val_list;

	vl->append(analyzer->BuildConnVal());
	vl->append(msg->BuildHdrVal());
	analyzer->ConnectionEvent(dns_end, vl);

	return 1;
	}

int DNS_Interpreter::ParseQuestions(DNS_MsgInfo* msg,
				const u_char*& data, int& len,
				const u_char* msg_start)
	{
	int n = msg->qdcount;

	while ( n > 0 && ParseQuestion(msg, data, len, msg_start) )
		--n;
	return n == 0;
	}

int DNS_Interpreter::ParseAnswers(DNS_MsgInfo* msg, int n, DNS_AnswerType atype,
				const u_char*& data, int& len,
				const u_char* msg_start)
	{
	msg->answer_type = atype;

	while ( n > 0 && ParseAnswer(msg, data, len, msg_start) )
		--n;

	return n == 0;
	}

int DNS_Interpreter::ParseQuestion(DNS_MsgInfo* msg,
				const u_char*& data, int& len,
				const u_char* msg_start)
	{
	u_char name[513];
	int name_len = sizeof(name) - 1;

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start);
	if ( ! name_end )
		return 0;

	if ( len < int(sizeof(short)) * 2 )
		{
		analyzer->Weird("DNS_truncated_quest_too_short");
		return 0;
		}

	EventHandlerPtr dns_event = 0;

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
			new BroString(name, name_end - name, 1);
		SendReplyOrRejectEvent(msg, dns_event, data, len, question_name);
		}
	else
		{
		// Consume the unused type/class.
		(void) ExtractShort(data, len);
		(void) ExtractShort(data, len);
		}

	return 1;
	}

int DNS_Interpreter::ParseAnswer(DNS_MsgInfo* msg,
				const u_char*& data, int& len,
				const u_char* msg_start)
	{
	u_char name[513];
	int name_len = sizeof(name) - 1;

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start);

	if ( ! name_end )
		return 0;

	if ( len < int(sizeof(short)) * 2 )
		{
		analyzer->Weird("DNS_truncated_ans_too_short");
		return 0;
		}

	// Note that the exact meaning of some of these fields will be
	// re-interpreted by other, more adventurous RR types.

	Unref(msg->query_name);
	msg->query_name = new StringVal(new BroString(name, name_end - name, 1));
	msg->atype = RR_Type(ExtractShort(data, len));
	msg->aclass = ExtractShort(data, len);
	msg->ttl = ExtractLong(data, len);

	int rdlength = ExtractShort(data, len);
	if ( rdlength > len )
		{
		analyzer->Weird("DNS_truncated_RR_rdlength_lt_len");
		return 0;
		}

	int status;
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
				status = 1;
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

		default:

			if ( dns_unknown_reply && ! msg->skip_event )
				{
				val_list* vl = new val_list;
				vl->append(analyzer->BuildConnVal());
				vl->append(msg->BuildHdrVal());
				vl->append(msg->BuildAnswerVal());
				analyzer->ConnectionEvent(dns_unknown_reply, vl);
				}

			analyzer->Weird("DNS_RR_unknown_type");
			data += rdlength;
			len -= rdlength;
			status = 1;
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

int DNS_Interpreter::ExtractLabel(const u_char*& data, int& len,
				u_char*& name, int& name_len,
				const u_char* msg_start)
	{
	if ( len <= 0 )
		return 0;

	const u_char* orig_data = data;
	int label_len = data[0];

	++data;
	--len;

	if ( len <= 0 )
		return 0;

	if ( label_len == 0 )
		// Found terminating label.
		return 0;

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
			return 0;
			}

		// Recursively resolve name.
		const u_char* recurse_data = msg_start + offset;
		int recurse_max_len = orig_data - recurse_data;

		u_char* name_end = ExtractName(recurse_data, recurse_max_len,
						name, name_len, msg_start);

		name_len -= name_end - name;
		name = name_end;

		return 0;
		}

	if ( label_len > len )
		{
		analyzer->Weird("DNS_label_len_gt_pkt");
		data += len;	// consume the rest of the packet
		len = 0;
		return 0;
		}

	if ( label_len > 63 &&
		// NetBIOS name service look ups can use longer labels.
		ntohs(analyzer->Conn()->RespPort()) != 137 )
		{
		analyzer->Weird("DNS_label_too_long");
		return 0;
		}

	if ( label_len >= name_len )
		{
		analyzer->Weird("DNS_label_len_gt_name_len");
		return 0;
		}

	memcpy(name, data, label_len);
	name[label_len] = '.';

	name += label_len + 1;
	name_len -= label_len + 1;

	data += label_len;
	len -= label_len;

	return 1;
	}

uint16 DNS_Interpreter::ExtractShort(const u_char*& data, int& len)
	{
	if ( len < 2 )
		return 0;

	uint16 val;

	val = data[0] << 8;

	++data;
	--len;

	val |= data[0];

	++data;
	--len;

	return val;
	}

uint32 DNS_Interpreter::ExtractLong(const u_char*& data, int& len)
	{
	if ( len < 4 )
		return 0;

	uint32 val;

	val = data[0] << 24;
	val |= data[1] << 16;
	val |= data[2] << 8;
	val |= data[3];

	data += sizeof(val);
	len -= sizeof(val);

	return val;
	}

int DNS_Interpreter::ParseRR_Name(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	const u_char* data_start = data;

	u_char name[513];
	int name_len = sizeof(name) - 1;

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start);
	if ( ! name_end )
		return 0;

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
			reply_event = 0;
	}

	if ( reply_event && ! msg->skip_event )
		{
		val_list* vl = new val_list;

		vl->append(analyzer->BuildConnVal());
		vl->append(msg->BuildHdrVal());
		vl->append(msg->BuildAnswerVal());
		vl->append(new StringVal(new BroString(name, name_end - name, 1)));

		analyzer->ConnectionEvent(reply_event, vl);
		}

	return 1;
	}

int DNS_Interpreter::ParseRR_SOA(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	const u_char* data_start = data;

	u_char mname[513];
	int mname_len = sizeof(mname) - 1;

	u_char* mname_end = ExtractName(data, len, mname, mname_len, msg_start);
	if ( ! mname_end )
		return 0;

	u_char rname[513];
	int rname_len = sizeof(rname) - 1;

	u_char* rname_end = ExtractName(data, len, rname, rname_len, msg_start);
	if ( ! rname_end )
		return 0;

	if ( len < 20 )
		return 0;

	uint32 serial = ExtractLong(data, len);
	uint32 refresh = ExtractLong(data, len);
	uint32 retry = ExtractLong(data, len);
	uint32 expire = ExtractLong(data, len);
	uint32 minimum = ExtractLong(data, len);

	if ( data - data_start != rdlength )
		analyzer->Weird("DNS_RR_length_mismatch");

	if ( dns_SOA_reply && ! msg->skip_event )
		{
		val_list* vl = new val_list;

		vl->append(analyzer->BuildConnVal());
		vl->append(msg->BuildHdrVal());
		vl->append(msg->BuildAnswerVal());

		RecordVal* r = new RecordVal(dns_soa);

		r->Assign(0, new StringVal(new BroString(mname, mname_end - mname, 1)));
		r->Assign(1, new StringVal(new BroString(rname, rname_end - rname, 1)));
		r->Assign(2, new Val(serial, TYPE_COUNT));
		r->Assign(3, new IntervalVal(double(refresh), Seconds));
		r->Assign(4, new IntervalVal(double(retry), Seconds));
		r->Assign(5, new IntervalVal(double(expire), Seconds));
		r->Assign(6, new IntervalVal(double(minimum), Seconds));

		vl->append(r);

		analyzer->ConnectionEvent(dns_SOA_reply, vl);
		}

	return 1;
	}

int DNS_Interpreter::ParseRR_MX(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	const u_char* data_start = data;

	int preference = ExtractShort(data, len);

	u_char name[513];
	int name_len = sizeof(name) - 1;

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start);
	if ( ! name_end )
		return 0;

	if ( data - data_start != rdlength )
		analyzer->Weird("DNS_RR_length_mismatch");

	if ( dns_MX_reply && ! msg->skip_event )
		{
		val_list* vl = new val_list;

		vl->append(analyzer->BuildConnVal());
		vl->append(msg->BuildHdrVal());
		vl->append(msg->BuildAnswerVal());
		vl->append(new StringVal(new BroString(name, name_end - name, 1)));
		vl->append(new Val(preference, TYPE_COUNT));

		analyzer->ConnectionEvent(dns_MX_reply, vl);
		}

	return 1;
	}

int DNS_Interpreter::ParseRR_NBS(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	data += rdlength;
	len -= rdlength;
	return 1;
	}

int DNS_Interpreter::ParseRR_SRV(DNS_MsgInfo* msg,
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
		return 0;

	if ( data - data_start != rdlength )
		analyzer->Weird("DNS_RR_length_mismatch");

	if ( dns_SRV_reply && ! msg->skip_event )
		{
		val_list* vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(msg->BuildHdrVal());
		vl->append(msg->BuildAnswerVal());
		vl->append(new StringVal(new BroString(name, name_end - name, 1)));
		vl->append(new Val(priority, TYPE_COUNT));
		vl->append(new Val(weight, TYPE_COUNT));
		vl->append(new Val(port, TYPE_COUNT));

		analyzer->ConnectionEvent(dns_SRV_reply, vl);
		}

	return 1;
	}

int DNS_Interpreter::ParseRR_EDNS(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	// We need a pair-value set mechanism here to dump useful information
	// out to the policy side of the house if rdlength > 0.

	if ( dns_EDNS_addl && ! msg->skip_event )
		{
		val_list* vl = new val_list;

		vl->append(analyzer->BuildConnVal());
		vl->append(msg->BuildHdrVal());
		vl->append(msg->BuildEDNS_Val());
		analyzer->ConnectionEvent(dns_EDNS_addl, vl);
		}

	// Currently EDNS supports the movement of type:data pairs
	// in the RR_DATA section.  Here's where we should put together
	// a corresponding mechanism.
	if ( rdlength > 0 )
		{ // deal with data
		data += rdlength;
		len -= rdlength;
		}
	else
		{ // no data, move on
		data += rdlength;
		len -= rdlength;
		}

	return 1;
	}

int DNS_Interpreter::ParseRR_TSIG(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	const u_char* data_start = data;
	u_char alg_name[1024];
	int alg_name_len = sizeof(alg_name) - 1;

	u_char* alg_name_end =
		ExtractName(data, len, alg_name, alg_name_len, msg_start);

	if ( ! alg_name_end )
		return 0;

	uint32 sign_time_sec = ExtractLong(data, len);
	unsigned int sign_time_msec = ExtractShort(data, len);
	unsigned int fudge = ExtractShort(data, len);

	u_char request_MAC[16];
	memcpy(request_MAC, data, sizeof(request_MAC));

	// Here we adjust the size of the requested MAC + u_int16_t
	// for length.  See RFC 2845, sec 2.3.
	int n = sizeof(request_MAC) + sizeof(u_int16_t);
	data += n;
	len -= n;

	unsigned int orig_id = ExtractShort(data, len);
	unsigned int rr_error = ExtractShort(data, len);

	msg->tsig = new TSIG_DATA;

	msg->tsig->alg_name =
		new BroString(alg_name, alg_name_end - alg_name, 1);
	msg->tsig->sig = new BroString(request_MAC, sizeof(request_MAC), 1);
	msg->tsig->time_s = sign_time_sec;
	msg->tsig->time_ms = sign_time_msec;
	msg->tsig->fudge = fudge;
	msg->tsig->orig_id = orig_id;
	msg->tsig->rr_error = rr_error;

	val_list* vl = new val_list;

	vl->append(analyzer->BuildConnVal());
	vl->append(msg->BuildHdrVal());
	vl->append(msg->BuildTSIG_Val());

	analyzer->ConnectionEvent(dns_TSIG_addl, vl);

	return 1;
	}

int DNS_Interpreter::ParseRR_A(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength)
	{
	if ( rdlength != 4 )
		{
		analyzer->Weird("DNS_RR_bad_length");
		return 0;
		}

	uint32 addr = ExtractLong(data, len);

	if ( dns_A_reply && ! msg->skip_event )
		{
		val_list* vl = new val_list;

		vl->append(analyzer->BuildConnVal());
		vl->append(msg->BuildHdrVal());
		vl->append(msg->BuildAnswerVal());
		vl->append(new AddrVal(htonl(addr)));

		analyzer->ConnectionEvent(dns_A_reply, vl);
		}

	return 1;
	}

int DNS_Interpreter::ParseRR_AAAA(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength)
	{
	uint32 addr[4];

	for ( int i = 0; i < 4; ++i )
		{
		addr[i] = htonl(ExtractLong(data, len));

		if ( len < 0 )
			{
			if ( msg->atype == TYPE_AAAA )
				analyzer->Weird("DNS_AAAA_neg_length");
			else
				analyzer->Weird("DNS_A6_neg_length");
			return 0;
			}
		}

	EventHandlerPtr event;
	if ( msg->atype == TYPE_AAAA )
		event = dns_AAAA_reply;
	else
		event = dns_A6_reply;
	if ( event && ! msg->skip_event )
		{
		val_list* vl = new val_list;

		vl->append(analyzer->BuildConnVal());
		vl->append(msg->BuildHdrVal());
		vl->append(msg->BuildAnswerVal());
		vl->append(new AddrVal(addr));
		analyzer->ConnectionEvent(event, vl);
		}

	return 1;
	}

int DNS_Interpreter::ParseRR_WKS(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength)
	{
	data += rdlength;
	len -= rdlength;

	return 1;
	}

int DNS_Interpreter::ParseRR_HINFO(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength)
	{
	data += rdlength;
	len -= rdlength;

	return 1;
	}

int DNS_Interpreter::ParseRR_TXT(DNS_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	int name_len = data[0];

	char* name = new char[name_len];

	memcpy(name, data+1, name_len);

	data += rdlength;
	len -= rdlength;

	if ( dns_TXT_reply && ! msg->skip_event )
		{
		val_list* vl = new val_list;

		vl->append(analyzer->BuildConnVal());
		vl->append(msg->BuildHdrVal());
		vl->append(msg->BuildAnswerVal());
		vl->append(new StringVal(name_len, name));

		analyzer->ConnectionEvent(dns_TXT_reply, vl);
		}

	delete [] name;

	return 1;
	}

void DNS_Interpreter::SendReplyOrRejectEvent(DNS_MsgInfo* msg,
						EventHandlerPtr event,
						const u_char*& data, int& len,
						BroString* question_name)
	{
	RR_Type qtype = RR_Type(ExtractShort(data, len));
	int qclass = ExtractShort(data, len);

	val_list* vl = new val_list;
	vl->append(analyzer->BuildConnVal());
	vl->append(msg->BuildHdrVal());
	vl->append(new StringVal(question_name));
	vl->append(new Val(qtype, TYPE_COUNT));
	vl->append(new Val(qclass, TYPE_COUNT));

	analyzer->ConnectionEvent(event, vl);
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

	query_name = 0;
	atype = TYPE_ALL;
	aclass = 0;
	ttl = 0;

	answer_type = DNS_QUESTION;
	skip_event = 0;
	tsig = 0;
	}

DNS_MsgInfo::~DNS_MsgInfo()
	{
	Unref(query_name);
	}

Val* DNS_MsgInfo::BuildHdrVal()
	{
	RecordVal* r = new RecordVal(dns_msg);

	r->Assign(0, new Val(id, TYPE_COUNT));
	r->Assign(1, new Val(opcode, TYPE_COUNT));
	r->Assign(2, new Val(rcode, TYPE_COUNT));
	r->Assign(3, new Val(QR, TYPE_BOOL));
	r->Assign(4, new Val(AA, TYPE_BOOL));
	r->Assign(5, new Val(TC, TYPE_BOOL));
	r->Assign(6, new Val(RD, TYPE_BOOL));
	r->Assign(7, new Val(RA, TYPE_BOOL));
	r->Assign(8, new Val(Z, TYPE_COUNT));
	r->Assign(9, new Val(qdcount, TYPE_COUNT));
	r->Assign(10, new Val(ancount, TYPE_COUNT));
	r->Assign(11, new Val(nscount, TYPE_COUNT));
	r->Assign(12, new Val(arcount, TYPE_COUNT));

	return r;
	}

Val* DNS_MsgInfo::BuildAnswerVal()
	{
	RecordVal* r = new RecordVal(dns_answer);

	Ref(query_name);
	r->Assign(0, new Val(int(answer_type), TYPE_COUNT));
	r->Assign(1, query_name);
	r->Assign(2, new Val(atype, TYPE_COUNT));
	r->Assign(3, new Val(aclass, TYPE_COUNT));
	r->Assign(4, new IntervalVal(double(ttl), Seconds));

	return r;
	}

Val* DNS_MsgInfo::BuildEDNS_Val()
	{
	// We have to treat the additional record type in EDNS differently
	// than a regular resource record.
	RecordVal* r = new RecordVal(dns_edns_additional);

	Ref(query_name);
	r->Assign(0, new Val(int(answer_type), TYPE_COUNT));
	r->Assign(1, query_name);

	// type = 0x29 or 41 = EDNS
	r->Assign(2, new Val(atype, TYPE_COUNT));

	// sender's UDP payload size, per RFC 2671 4.3
	r->Assign(3, new Val(aclass, TYPE_COUNT));

	// Need to break the TTL field into three components:
	// initial: [------------- ttl (32) ---------------------]
	// after:   [DO][ ext rcode (7)][ver # (8)][ Z field (16)]

	unsigned int ercode = (ttl >> 24) & 0xff;
	unsigned int version = (ttl >> 16) & 0xff;
	// unsigned int DO = ttl & 0x8000;	// "DNSSEC OK" - RFC 3225
	unsigned int z = ttl & 0xffff;

	unsigned int return_error = (ercode << 8) | rcode;

	r->Assign(4, new Val(return_error, TYPE_COUNT));
	r->Assign(5, new Val(version, TYPE_COUNT));
	r->Assign(6, new Val(z, TYPE_COUNT));
	r->Assign(7, new IntervalVal(double(ttl), Seconds));
	r->Assign(8, new Val(is_query, TYPE_COUNT));

	return r;
	}

Val* DNS_MsgInfo::BuildTSIG_Val()
	{
	RecordVal* r = new RecordVal(dns_tsig_additional);
	double rtime = tsig->time_s + tsig->time_ms / 1000.0;

	Ref(query_name);
	// r->Assign(0, new Val(int(answer_type), TYPE_COUNT));
	r->Assign(0, query_name);
	r->Assign(1, new Val(int(answer_type), TYPE_COUNT));
	r->Assign(2, new StringVal(tsig->alg_name));
	r->Assign(3, new StringVal(tsig->sig));
	r->Assign(4, new Val(rtime, TYPE_TIME));
	r->Assign(5, new Val(double(tsig->fudge), TYPE_TIME));
	r->Assign(6, new Val(tsig->orig_id, TYPE_COUNT));
	r->Assign(7, new Val(tsig->rr_error, TYPE_COUNT));
	r->Assign(8, new Val(is_query, TYPE_COUNT));

	delete tsig;
	tsig = 0;

	return r;
	}

Contents_DNS::Contents_DNS(Connection* conn, bool orig,
				DNS_Interpreter* arg_interp)
: tcp::TCP_SupportAnalyzer("CONTENTS_DNS", conn, orig)
	{
	interp = arg_interp;

	msg_buf = 0;
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
		interp->ParseMessage(msg_buf, buf_n, true);
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

	ForwardPacket(msg_size, msg_buf, orig, -1, 0, 0);

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
	contents_dns_orig = contents_dns_resp = 0;
	did_session_done = 0;

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
					network_time + dns_session_timeout, 1,
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

	if ( Conn()->ConnTransport() == TRANSPORT_UDP && ! did_session_done )
		Event(udp_session_done);
	else
		interp->Timeout();
	}

void DNS_Analyzer::DeliverPacket(int len, const u_char* data, bool orig,
					int seq, const IP_Hdr* ip, int caplen)
	{
	tcp::TCP_ApplicationAnalyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

	if ( orig )
		{
		if ( ! interp->ParseMessage(data, len, 1) && non_dns_request )
			{
			val_list* vl = new val_list;
			vl->append(BuildConnVal());
			vl->append(new StringVal(len, (const char*) data));
			ConnectionEvent(non_dns_request, vl);
			}
		}

	else
		interp->ParseMessage(data, len, 0);
	}


void DNS_Analyzer::ConnectionClosed(tcp::TCP_Endpoint* endpoint, tcp::TCP_Endpoint* peer,
					int gen_event)
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
				t + dns_session_timeout, 1, TIMER_DNS_EXPIRE);
	}
