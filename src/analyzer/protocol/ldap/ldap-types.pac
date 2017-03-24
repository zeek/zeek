# Types from KRB

%header{
Val* GetStringFromPrincipalName(const KRB_Principal_Name* pname);

%}

%code{
Val* GetStringFromPrincipalName(const KRB_Principal_Name* pname)
{
	if ( pname->data()->size() == 1 )
		return bytestring_to_val(pname->data()[0][0]->encoding()->content());
	if ( pname->data()->size() == 2 )
		return new StringVal(fmt("%s/%s", (char *) pname->data()[0][0]->encoding()->content().begin(), (char *)pname->data()[0][1]->encoding()->content().begin()));
    if ( pname->data()->size() == 3 )
       	return new StringVal(fmt("%s/%s/%s", (char *) pname->data()[0][0]->encoding()->content().begin(), (char *)pname->data()[0][1]->encoding()->content().begin(),(char *)pname->data()[0][2]->encoding()->content().begin()));
	return new StringVal("unknown");
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
