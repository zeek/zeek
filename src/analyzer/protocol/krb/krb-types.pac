# Fundamental KRB types

%header{
zeek::ValPtr GetStringFromPrincipalName(const KRB_Principal_Name* pname);

zeek::VectorValPtr proc_cipher_list(const Array* list);

zeek::VectorValPtr proc_host_address_list(const ZeekAnalyzer a, const KRB_Host_Addresses* list);
zeek::RecordValPtr proc_host_address(const ZeekAnalyzer a, const KRB_Host_Address* addr);

zeek::VectorValPtr proc_tickets(const KRB_Ticket_Sequence* list);
zeek::RecordValPtr proc_ticket(const KRB_Ticket* ticket);
%}

%code{
zeek::ValPtr GetStringFromPrincipalName(const KRB_Principal_Name* pname)
{
	if ( pname->data()->size() == 1 )
		return to_stringval(pname->data()[0][0]->encoding()->content());
	if ( pname->data()->size() == 2 )
		return zeek::make_intrusive<zeek::StringVal>(zeek::util::fmt("%s/%s", (char *) pname->data()[0][0]->encoding()->content().begin(), (char *)pname->data()[0][1]->encoding()->content().begin()));
	if ( pname->data()->size() == 3 ) // if the name-string has a third value, this will just append it, else this will return unknown as the principal name
		return zeek::make_intrusive<zeek::StringVal>(zeek::util::fmt("%s/%s/%s", (char *) pname->data()[0][0]->encoding()->content().begin(), (char *)pname->data()[0][1]->encoding()->content().begin(), (char *)pname->data()[0][2]->encoding()->content().begin()));

	return zeek::make_intrusive<zeek::StringVal>("unknown");
}

zeek::VectorValPtr proc_cipher_list(const Array* list)
{
	auto ciphers = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);
	for ( uint i = 0; i < list->data()->size(); ++i )
		ciphers->Assign(ciphers->Size(), asn1_integer_to_val((*list->data())[i], zeek::TYPE_COUNT));
	return ciphers;
}

zeek::VectorValPtr proc_host_address_list(const ZeekAnalyzer a, const KRB_Host_Addresses* list)
{
	auto addrs = zeek::make_intrusive<zeek::VectorVal>(zeek::id::find_type<zeek::VectorType>("KRB::Host_Address_Vector"));

	for ( uint i = 0; i < list->addresses()->size(); ++i )
		{
		addrs->Assign(addrs->Size(), proc_host_address(a, (*list->addresses())[i]));
		}

	return addrs;
}

zeek::RecordValPtr proc_host_address(const ZeekAnalyzer a, const KRB_Host_Address* addr)
{
	auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::KRB::Host_Address);
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
			rv->Assign(0, zeek::make_intrusive<zeek::AddrVal>(zeek::IPAddr(IPv4, bytes, zeek::IPAddr::Network)));
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
			rv->Assign(0, zeek::make_intrusive<zeek::AddrVal>(zeek::IPAddr(IPv6, bytes, zeek::IPAddr::Network)));
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

	auto unk = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::KRB::Type_Value);
	unk->Assign(0, asn1_integer_to_val(addr->addr_type(), zeek::TYPE_COUNT));
	unk->Assign(1, to_stringval(addr_bytes));
	rv->Assign(2, std::move(unk));
	return rv;
}

zeek::VectorValPtr proc_tickets(const KRB_Ticket_Sequence* list)
	{
	auto tickets = zeek::make_intrusive<zeek::VectorVal>(zeek::id::find_type<zeek::VectorType>("KRB::Ticket_Vector"));

	for ( uint i = 0; i < list->tickets()->size(); ++i )
		{
		KRB_Ticket* element = (*list->tickets())[i];
		tickets->Assign(tickets->Size(), proc_ticket(element));
		}

	return tickets;
	}

zeek::RecordValPtr proc_ticket(const KRB_Ticket* ticket)
	{
	auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::KRB::Ticket);

	rv->Assign(0, asn1_integer_to_val(ticket->tkt_vno()->data(), zeek::TYPE_COUNT));
	rv->Assign(1, to_stringval(ticket->realm()->data()->content()));
	rv->Assign(2, GetStringFromPrincipalName(ticket->sname()));
	rv->Assign(3, asn1_integer_to_val(ticket->enc_part()->data()->etype()->data(), zeek::TYPE_COUNT));
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
