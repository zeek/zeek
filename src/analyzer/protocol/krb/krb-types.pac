# Fundamental KRB types

%header{
Val* GetStringFromPrincipalName(const KRB_Principal_Name* pname);

VectorVal* proc_cipher_list(const Array* list);
VectorVal* proc_host_address_list(const KRB_Host_Addresses* list);
VectorVal* proc_tickets(const KRB_Ticket_Sequence* list);
%}

%code{
Val* GetStringFromPrincipalName(const KRB_Principal_Name* pname)
{
	if ( pname->data()->size() == 1 )
 		return bytestring_to_val(pname->data()[0][0]->encoding()->content());
 	if ( pname->data()->size() == 2 )
 		return new StringVal(fmt("%s/%s", (char *) pname->data()[0][0]->encoding()->content().begin(), (char *)pname->data()[0][1]->encoding()->content().begin()));

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
		RecordVal* addr = new RecordVal(BifType::Record::KRB::Host_Address);
		KRB_Host_Address* element = (*list->addresses())[i];
		
		switch ( binary_to_int64(element->addr_type()->encoding()->content()) )
			{
			case 2:
				addr->Assign(0, new AddrVal(IPAddr(IPv4, 
						    	           (const uint32_t*) c_str(element->address()->data()->content()), 
								   IPAddr::Network)));
				break;
			case 24:
				addr->Assign(0, new AddrVal(IPAddr(IPv6, 
						    		   (const uint32_t*) c_str(element->address()->data()->content()), 
								   IPAddr::Network)));
				break;
			case 20:
				addr->Assign(1, bytestring_to_val(element->address()->data()->content()));
				break;
			default:
				RecordVal* unk = new RecordVal(BifType::Record::KRB::Type_Value);
				unk->Assign(0, asn1_integer_to_val(element->addr_type(), TYPE_COUNT));
				unk->Assign(1, bytestring_to_val(element->address()->data()->content()));
				addr->Assign(2, unk);
				break;
			}
		addrs->Assign(addrs->Size(), addr);
		}

	return addrs;	
}


VectorVal* proc_tickets(const KRB_Ticket_Sequence* list)
{
	VectorVal* tickets = new VectorVal(internal_type("KRB::Ticket_Vector")->AsVectorType());
	for ( uint i = 0; i < list->tickets()->size(); ++i )
		{
		KRB_Ticket* element = (*list->tickets())[i];
		RecordVal* ticket = new RecordVal(BifType::Record::KRB::Ticket);

		ticket->Assign(0, asn1_integer_to_val(element->tkt_vno()->data(), TYPE_COUNT));
		ticket->Assign(1, bytestring_to_val(element->realm()->data()->content()));
		ticket->Assign(2, GetStringFromPrincipalName(element->sname()));
		ticket->Assign(3, asn1_integer_to_val(element->enc_part()->etype()->data(), TYPE_COUNT));
		tickets->Assign(tickets->Size(), ticket);
		}
	
	return tickets;
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
	enc_part  : KRB_Encrypted_Data;
};

type KRB_Ticket_Sequence = record {
	seq_meta : ASN1EncodingMeta;
	tickets  : KRB_Ticket(true)[] &length=seq_meta.length;
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

