# Fundamental KRB types

%header{
Val* GetStringFromPrincipalName(const KRB_Principal_Name* pname);

VectorVal* proc_cipher_list(const Array* list);

VectorVal* proc_host_address_list(const KRB_Host_Addresses* list);
RecordVal* proc_host_address(const KRB_Host_Address* addr);

VectorVal* proc_tickets(const KRB_Ticket_Sequence* list);
RecordVal* proc_ticket(const KRB_Ticket* ticket);
%}

%code{
Val* GetStringFromPrincipalName(const KRB_Principal_Name* pname)
{
	if ( pname->data()->size() == 1 )
		return bytestring_to_val(pname->data()[0][0]->encoding()->content());
	if ( pname->data()->size() == 2 )
		return new StringVal(fmt("%s/%s", (char *) pname->data()[0][0]->encoding()->content().begin(), (char *)pname->data()[0][1]->encoding()->content().begin()));
	if ( pname->data()->size() == 3 ) // if the name-string has a third value, this will just append it, else this will return unknown as the principal name
		return new StringVal(fmt("%s/%s/%s", (char *) pname->data()[0][0]->encoding()->content().begin(), (char *)pname->data()[0][1]->encoding()->content().begin(), (char *)pname->data()[0][2]->encoding()->content().begin()));

	return new StringVal("unknown");
}

VectorVal* proc_cipher_list(const Array* list)
{
	VectorVal* ciphers = new VectorVal(internal_type("index_vec")->AsVectorType());
	for ( uint i = 0; i < list->data()->size(); ++i )
		ciphers->Assign(ciphers->Size(), asn1_integer_to_val((*list->data())[i], TYPE_COUNT));
	return ciphers;
}

VectorVal* proc_host_address_list(const KRB_Host_Addresses* list)
{
	VectorVal* addrs = new VectorVal(internal_type("KRB::Host_Address_Vector")->AsVectorType());

	for ( uint i = 0; i < list->addresses()->size(); ++i )
		{
		addrs->Assign(addrs->Size(), proc_host_address((*list->addresses())[i]));
		}

	return addrs;
}

RecordVal* proc_host_address(const KRB_Host_Address* addr)
{
	RecordVal* rv = new RecordVal(BifType::Record::KRB::Host_Address);

	switch ( binary_to_int64(addr->addr_type()->encoding()->content()) )
		{
		case 2:
			rv->Assign(0, new AddrVal(IPAddr(IPv4,
					    	         (const uint32_t*) c_str(addr->address()->data()->content()),
							 IPAddr::Network)));
			break;
		case 24:
			rv->Assign(0, new AddrVal(IPAddr(IPv6,
					    		 (const uint32_t*) c_str(addr->address()->data()->content()),
							 IPAddr::Network)));
			break;
		case 20:
			rv->Assign(1, bytestring_to_val(addr->address()->data()->content()));
			break;
		default:
			RecordVal* unk = new RecordVal(BifType::Record::KRB::Type_Value);
			unk->Assign(0, asn1_integer_to_val(addr->addr_type(), TYPE_COUNT));
			unk->Assign(1, bytestring_to_val(addr->address()->data()->content()));
			rv->Assign(2, unk);
			break;
		}

	return rv;
}

VectorVal* proc_tickets(const KRB_Ticket_Sequence* list)
{
	VectorVal* tickets = new VectorVal(internal_type("KRB::Ticket_Vector")->AsVectorType());
	for ( uint i = 0; i < list->tickets()->size(); ++i )
		{
		KRB_Ticket* element = (*list->tickets())[i];
		tickets->Assign(tickets->Size(), proc_ticket(element));
		}

	return tickets;
}

RecordVal* proc_ticket(const KRB_Ticket* ticket)
{
	RecordVal* rv = new RecordVal(BifType::Record::KRB::Ticket);

	rv->Assign(0, asn1_integer_to_val(ticket->tkt_vno()->data(), TYPE_COUNT));
	rv->Assign(1, bytestring_to_val(ticket->realm()->data()->content()));
	rv->Assign(2, GetStringFromPrincipalName(ticket->sname()));
	rv->Assign(3, asn1_integer_to_val(ticket->enc_part()->data()->etype()->data(), TYPE_COUNT));

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
	ciphertext	: bytestring &length=have_kvno ? next_meta.length : kvno_meta.length;
} &let {
	have_kvno	: bool = kvno_meta.index == 1;
};

type KRB_Checksum = record {
	checksum_type: SequenceElement(true);
	checksum     : SequenceElement(true);
};

