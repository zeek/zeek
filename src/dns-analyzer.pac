# $Id:$

%extern{
#include <set>
%}

%code{
int add_to_name_buffer(DNS_name* name, char* buf, const int buf_n, int buf_i)
	{
	for ( int i = 0; i < int(name->labels()->size()); ++i )
		{
		DNS_label* label = (*name->labels())[i];
		if ( label->label_type() == 0 )
			{
			bytestring const &label_str = label->label();
			if ( buf_i > 0 && buf_i < buf_n )
				buf[buf_i++] = '.';
			BINPAC_ASSERT(buf_i + label_str.length() <= buf_n);
			memcpy(buf + buf_i, label_str.begin(),
				label_str.length());
			buf_i += label_str.length();
			}
		else if ( label->label_type() == 3 )
			{
			return add_to_name_buffer(label->ptr(), buf,
							buf_n, buf_i);
			}
		}

	return buf_i;
	}

StringVal* name_to_val(DNS_name* name)
	{
	char name_buf[520];
	int n = add_to_name_buffer(name, name_buf, sizeof(name_buf), 0);
	if ( n > 0 )
		--n;  // remove the trailing '.'

	BINPAC_ASSERT(n < int(sizeof(name_buf)));

	name_buf[n] = 0;
	for ( int i = 0; i < n; ++i )
		if ( isupper(name_buf[i]) )
			name_buf[i] = tolower(name_buf[i]);

	return new StringVal(name_buf);
	}
%}

connection DNS_Conn(bro_analyzer: BroAnalyzer)
{
	upflow = DNS_Flow;
	downflow = DNS_Flow;
};

flow DNS_Flow
{
	datagram = DNS_message withcontext(connection, this);

	%member{
		set<int> pointer_set;
		BroVal dns_msg_val_;
	%}

	%init{
		dns_msg_val_ = 0;
	%}

	%cleanup{
		Unref(dns_msg_val_);
		dns_msg_val_ = 0;
	%}

	# Return a byte segment starting at <offset> in the original message.
	function get_pointer(msgdata: const_bytestring,
				offset: int): const_bytestring
		%{
		if ( offset < 0 || offset >= msgdata.length() )
			return const_bytestring(0, 0);

		if ( pointer_set.find(offset) != pointer_set.end() )
			throw Exception("DNS pointer loop!");

		pointer_set.insert(offset);
		return const_bytestring(msgdata.begin() + offset, msgdata.end());
		%}

	function reset_pointer_set(): bool
		%{
		pointer_set.clear();
		return true;
		%}

	function process_dns_header(hdr: DNS_header): bool
		%{
		Unref(dns_msg_val_);

		RecordVal* r = new RecordVal(dns_msg);

		r->Assign(0, new Val(${hdr.id}, TYPE_COUNT));
		r->Assign(1, new Val(${hdr.opcode}, TYPE_COUNT));
		r->Assign(2, new Val(${hdr.rcode}, TYPE_COUNT));
		r->Assign(3, new Val(${hdr.qr}, TYPE_BOOL));
		r->Assign(4, new Val(${hdr.aa}, TYPE_BOOL));
		r->Assign(5, new Val(${hdr.tc}, TYPE_BOOL));
		r->Assign(6, new Val(${hdr.rd}, TYPE_BOOL));
		r->Assign(7, new Val(${hdr.ra}, TYPE_BOOL));
		r->Assign(8, new Val(${hdr.z}, TYPE_COUNT));

		r->Assign(9, new Val(${hdr.qdcount}, TYPE_COUNT));
		r->Assign(10, new Val(${hdr.ancount}, TYPE_COUNT));
		r->Assign(11, new Val(${hdr.nscount}, TYPE_COUNT));
		r->Assign(12, new Val(${hdr.arcount}, TYPE_COUNT));

		dns_msg_val_ = r;

		return true;
		%}

	function process_dns_question(question: DNS_question): bool
		%{
		DNS_message* msg = question->msg();

		if ( msg->header()->qr() == 0 )
			{
			bro_event_dns_request(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				dns_msg_val_->Ref(),
				name_to_val(question->qname()),
				question->qtype(),
				question->qclass());
			}

		else if ( msg->header()->ancount() == 0 &&
		          msg->header()->nscount() == 0 &&
		          msg->header()->arcount() == 0 )
			{
			bro_event_dns_rejected(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				dns_msg_val_->Ref(),
				name_to_val(question->qname()),
				question->qtype(),
				question->qclass());
			}

		return true;
		%}

	function build_dns_answer(rr: DNS_rr): BroVal
		%{
		RecordVal* r = new RecordVal(dns_answer);

		r->Assign(0, new Val(rr->answer_type(), TYPE_COUNT));
		r->Assign(1, name_to_val(rr->rr_name()));
		r->Assign(2, new Val(rr->rr_type(), TYPE_COUNT));
		r->Assign(3, new Val(rr->rr_class(), TYPE_COUNT));
		r->Assign(4, new IntervalVal(double(rr->rr_ttl()), Seconds));

		return r;
		%}

	function build_dns_soa(soa: DNS_rdata_SOA): BroVal
		%{
		RecordVal* r = new RecordVal(dns_soa);

		r->Assign(0, name_to_val(soa->mname()));
		r->Assign(1, name_to_val(soa->rname()));
		r->Assign(2, new Val(soa->serial(), TYPE_COUNT));
		r->Assign(3, new IntervalVal(double(soa->refresh()), Seconds));
		r->Assign(4, new IntervalVal(double(soa->retry()), Seconds));
		r->Assign(5, new IntervalVal(double(soa->expire()), Seconds));
		r->Assign(6, new IntervalVal(double(soa->minimum()), Seconds));

		return r;
		%}

	function build_edns_additional(rr: DNS_rr): BroVal
		%{
		// We have to treat the additional record type in EDNS
		// differently than a regular resource record.
		RecordVal* r = new RecordVal(dns_edns_additional);

		r->Assign(0, new Val(int(rr->answer_type()), TYPE_COUNT));
		r->Assign(1, name_to_val(rr->rr_name()));

		// Type = 0x29 or 41 = EDNS
		r->Assign(2, new Val(rr->rr_type(), TYPE_COUNT));

		// Sender's UDP payload size, per RFC 2671 4.3
		r->Assign(3, new Val(rr->rr_class(), TYPE_COUNT));

		// Need to break the TTL field into three components:
		// initial: [------------- ttl (32) ---------------------]
		// after:   [DO][ ext rcode (7)][ver # (8)][ Z field (16)]

		unsigned int ercode =  (rr->rr_ttl() & 0xff000000) >> 24;
		unsigned int version = (rr->rr_ttl() & 0x00ff0000) >> 16;
		unsigned int z =       (rr->rr_ttl() & 0x0000ffff);

		int rcode = rr->msg()->header()->rcode();
		unsigned int return_error = (ercode << 8) | rcode;

		r->Assign(4, new Val(return_error, TYPE_COUNT));
		r->Assign(5, new Val(version, TYPE_COUNT));
		r->Assign(6, new Val(z, TYPE_COUNT));
		r->Assign(7, new IntervalVal(double(rr->rr_ttl()), Seconds));
		r->Assign(8, new Val(rr->msg()->header()->qr() == 0, TYPE_COUNT));

		return r;
		%}

	function process_dns_rr(rr: DNS_rr): bool
		%{
		const DNS_rdata* rd = rr->rr_rdata();

		switch ( rr->rr_type() ) {
		case TYPE_A:
		case TYPE_A6:
		case TYPE_AAAA:
			if ( ! dns_A_reply )
				break;

#ifdef BROv6
			::uint32 addr[4];
#else
			addr_type addr;
#endif

			if ( rr->rr_type() == TYPE_A )
				{
#ifdef BROv6
				addr[0] = addr[1] = addr[2] = 0;
				addr[3] = htonl(rd->type_a());
#else
				addr = htonl(rd->type_a());
#endif
				}

			else
				{
#ifdef BROv6
				for ( int i = 0; i < 4; ++i )
					addr[i] = htonl((*rd->type_aaaa())[i]);
#else
				addr = htonl((*rd->type_aaaa())[3]);
#endif
				}

			// For now, we treat A6 and AAAA as A's.  Given the
			// above fixes for BROv6, we can probably now introduce
			// their own events.  (It's not clear A6 is needed -
			// do we actually encounter it in practice?)
			bro_event_dns_A_reply(connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				dns_msg_val_->Ref(), build_dns_answer(rr), addr);
			break;

		case TYPE_NS:
			if ( dns_NS_reply )
				{
				bro_event_dns_NS_reply(connection()->bro_analyzer(),
					connection()->bro_analyzer()->Conn(),
					dns_msg_val_->Ref(),
					build_dns_answer(rr),
					name_to_val(rr->rr_rdata()->type_ns()));
				}
			break;

		case TYPE_CNAME:
			if ( dns_CNAME_reply )
				{
				bro_event_dns_CNAME_reply(
					connection()->bro_analyzer(),
					connection()->bro_analyzer()->Conn(),
					dns_msg_val_->Ref(),
					build_dns_answer(rr),
					name_to_val(rr->rr_rdata()->type_cname()));
				}
			break;

		case TYPE_SOA:
			if ( dns_SOA_reply )
				{
				bro_event_dns_SOA_reply(
					connection()->bro_analyzer(),
					connection()->bro_analyzer()->Conn(),
					dns_msg_val_->Ref(),
					build_dns_answer(rr),
					build_dns_soa(rr->rr_rdata()->type_soa()));
				}
			break;

		case TYPE_PTR:
			if ( dns_PTR_reply )
				{
				bro_event_dns_PTR_reply(
					connection()->bro_analyzer(),
					connection()->bro_analyzer()->Conn(),
					dns_msg_val_->Ref(),
					build_dns_answer(rr),
					name_to_val(rr->rr_rdata()->type_ptr()));
				}
			break;

		case TYPE_MX:
			if ( dns_MX_reply )
				{
				bro_event_dns_MX_reply(
					connection()->bro_analyzer(),
					connection()->bro_analyzer()->Conn(),
					dns_msg_val_->Ref(),
					build_dns_answer(rr),
					name_to_val(rr->rr_rdata()->type_mx()->name()),
					rr->rr_rdata()->type_mx()->preference());
				}
			break;

		case TYPE_EDNS:
			if ( dns_EDNS_addl )
				{
				bro_event_dns_EDNS_addl(
					connection()->bro_analyzer(),
					connection()->bro_analyzer()->Conn(),
					dns_msg_val_->Ref(),
					build_edns_additional(rr));
				}
			break;
		}

		return true;
		%}
};

refine typeattr DNS_header += &let {
	proc_dns_header = $context.flow.process_dns_header(this);
};

refine typeattr DNS_question += &let {
	proc_dns_question = $context.flow.process_dns_question(this);
};

refine typeattr DNS_rr += &let {
	proc_dns_rr = $context.flow.process_dns_rr(this);
};
