# Fundamental KRB types

%header{
IntrusivePtr<Val> GetStringFromPrincipalName(const KRB_Principal_Name* pname);

VectorVal* proc_cipher_list(const Array* list);

VectorVal* proc_host_address_list(const BroAnalyzer a, const KRB_Host_Addresses* list);
RecordVal* proc_host_address(const BroAnalyzer a, const KRB_Host_Address* addr);

IntrusivePtr<VectorVal> proc_tickets(const KRB_Ticket_Sequence* list);
IntrusivePtr<RecordVal> proc_ticket(const KRB_Ticket* ticket);
%}

%code{
IntrusivePtr<Val> GetStringFromPrincipalName(const KRB_Principal_Name* pname)
{
	if ( pname->data()->size() == 1 )
		return to_stringval(pname->data()[0][0]->encoding()->content());
	if ( pname->data()->size() == 2 )
		return make_intrusive<StringVal>(fmt("%s/%s", (char *) pname->data()[0][0]->encoding()->content().begin(), (char *)pname->data()[0][1]->encoding()->content().begin()));
	if ( pname->data()->size() == 3 ) // if the name-string has a third value, this will just append it, else this will return unknown as the principal name
		return make_intrusive<StringVal>(fmt("%s/%s/%s", (char *) pname->data()[0][0]->encoding()->content().begin(), (char *)pname->data()[0][1]->encoding()->content().begin(), (char *)pname->data()[0][2]->encoding()->content().begin()));

	return make_intrusive<StringVal>("unknown");
}

VectorVal* proc_cipher_list(const Array* list)
{
	auto ciphers = make_intrusive<VectorVal>(zeek::vars::index_vec);
	for ( uint i = 0; i < list->data()->size(); ++i )
		ciphers->Assign(ciphers->Size(), asn1_integer_to_val((*list->data())[i], TYPE_COUNT));
	return ciphers.release();
}

VectorVal* proc_host_address_list(const BroAnalyzer a, const KRB_Host_Addresses* list)
{
	auto addrs = make_intrusive<VectorVal>(zeek::lookup_type<VectorType>("KRB::Host_Address_Vector"));

	for ( uint i = 0; i < list->addresses()->size(); ++i )
		{
		addrs->Assign(addrs->Size(), proc_host_address(a, (*list->addresses())[i]));
		}

	return addrs.release();
}

RecordVal* proc_host_address(const BroAnalyzer a, const KRB_Host_Address* addr)
{
	RecordVal* rv = new RecordVal(BifType::Record::KRB::Host_Address);
	const auto& addr_bytes = addr->address()->data()->content();

	switch ( binary_to_int64(addr->addr_type()->encoding()->content()) )
		{
		case 2:
			{
			if ( addr_bytes.length() != 4 )
				{
				a->Weird("invalid_kerberos_addr_len");
				break;
				}

			auto bytes = reinterpret_cast<const uint32_t*>(addr_bytes.data());
			rv->Assign(0, make_intrusive<AddrVal>(IPAddr(IPv4, bytes, IPAddr::Network)));
			return rv;
			}
		case 24:
			{
			if ( addr_bytes.length() != 16 )
				{
				a->Weird("invalid_kerberos_addr_len");
				break;
				}

			auto bytes = reinterpret_cast<const uint32_t*>(addr_bytes.data());
			rv->Assign(0, make_intrusive<AddrVal>(IPAddr(IPv6, bytes, IPAddr::Network)));
			return rv;
			}
		case 20:
			{
			rv->Assign(1, to_stringval(addr_bytes));
			return rv;
			}
		default:
			break;
		}

	RecordVal* unk = new RecordVal(BifType::Record::KRB::Type_Value);
	unk->Assign(0, asn1_integer_to_val(addr->addr_type(), TYPE_COUNT));
	unk->Assign(1, to_stringval(addr_bytes));
	rv->Assign(2, unk);
	return rv;
}

IntrusivePtr<VectorVal> proc_tickets(const KRB_Ticket_Sequence* list)
	{
	auto tickets = make_intrusive<VectorVal>(zeek::lookup_type<VectorType>("KRB::Ticket_Vector"));

	for ( uint i = 0; i < list->tickets()->size(); ++i )
		{
		KRB_Ticket* element = (*list->tickets())[i];
		tickets->Assign(tickets->Size(), proc_ticket(element));
		}

	return tickets;
	}

IntrusivePtr<RecordVal> proc_ticket(const KRB_Ticket* ticket)
	{
	auto rv = make_intrusive<RecordVal>(BifType::Record::KRB::Ticket);

	rv->Assign(0, asn1_integer_to_val(ticket->tkt_vno()->data(), TYPE_COUNT));
	rv->Assign(1, to_stringval(ticket->realm()->data()->content()));
	rv->Assign(2, GetStringFromPrincipalName(ticket->sname()));
	rv->Assign(3, asn1_integer_to_val(ticket->enc_part()->data()->etype()->data(), TYPE_COUNT));
	rv->Assign(4, to_stringval(ticket->enc_part()->data()->ciphertext()->encoding()->content()));

	return rv;
	}
%}

type KRB_Principal_Name = record {
	seq_meta  : ASN1EncodingMeta;
	name_meta : ASN1EncodingMeta;
	name_type : ASN1Integer;
	seq_meta_1: ASN1EncodingMeta;
	seq_meta_2: ASN1EncodingMeta;
	data      : ASN1OctetString[];
};

type KRB_Time = record {
	meta: ASN1EncodingMeta;
	time: bytestring &restofdata;
};

type KRB_Host_Addresses = record {
	seq_meta : ASN1EncodingMeta;
	addresses: KRB_Host_Address[];
};

type KRB_Host_Address = record {
	addr_type_meta	: SequenceElement(false);
	addr_type	: ASN1Integer;
	address  	: SequenceElement(true);
};

type KRB_Ticket(in_sequence: bool) = record {
	have_seq  : case in_sequence of {
		true  -> meta: ASN1EncodingMeta;
		false -> none: empty;
	};
	app_meta  : ASN1EncodingMeta;
	seq_meta  : ASN1EncodingMeta;
	tkt_vno   : SequenceElement(true);
	realm	  : SequenceElement(true);
	sname_meta: ASN1EncodingMeta;
	sname	  : KRB_Principal_Name &length=sname_meta.length;
	enc_part  : KRB_Encrypted_Data_in_Seq;
};

type KRB_Ticket_Sequence = record {
	seq_meta : ASN1EncodingMeta;
	tickets  : KRB_Ticket(false)[] &length=seq_meta.length;
};

type KRB_Encrypted_Data_in_Seq = record {
	index_meta  : ASN1EncodingMeta;
	data	    : KRB_Encrypted_Data &length=index_meta.length;
};

type KRB_Encrypted_Data = record {
	seq_meta	: ASN1EncodingMeta;
	etype		: SequenceElement(true);
	kvno_meta	: ASN1EncodingMeta;
	case_kvno	: case have_kvno of {
		true   -> kvno	: ASN1Integer;
		false  -> none	: empty;
	};
	grab_next_meta	: case have_kvno of {
		true   -> next_meta: ASN1EncodingMeta;
		false  -> none_meta: empty;
	};
	ciphertext	: ASN1OctetString &length=have_kvno ? next_meta.length : kvno_meta.length;
} &let {
	have_kvno	: bool = kvno_meta.index == 1;
};

type KRB_Checksum = record {
	checksum_type: SequenceElement(true);
	checksum     : SequenceElement(true);
};

