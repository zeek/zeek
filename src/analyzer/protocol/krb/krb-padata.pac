# Kerberos pre-authentication data is a significant piece of the complexity,
# so we're splitting this off

type KRB_PA_Data_Optional(pkt_type: uint8, desired_index: uint8) = record {
	first_meta	: ASN1EncodingMeta;
	padata		: KRB_PA_Data_Field(has_padata, pkt_type, first_meta.length);
	next_meta	: ASN1OptionalEncodingMeta(has_padata, first_meta);
} &let {
	has_padata : bool = first_meta.index == desired_index;
};

type KRB_PA_Data_Field(is_present: bool, pkt_type: uint8, length: uint64) = case is_present of {
	true -> padata: KRB_PA_Data_Sequence(pkt_type) &length=length;
	false -> none: empty;
};

type KRB_PA_Data_Sequence(pkt_type: uint8) = record {
	seq_meta    : ASN1EncodingMeta;
	padata_elems: KRB_PA_Data(pkt_type)[];
};

type KRB_PA_Data(pkt_type: uint8) = record {
	seq_meta	  : ASN1EncodingMeta;
	pa_data_type      : SequenceElement(true);
	pa_data_elem_meta : ASN1EncodingMeta;
	have_data	  : case pkt_type of {
		KRB_ERROR   -> pa_data_placeholder: bytestring &length=pa_data_elem_meta.length;
		default	    -> pa_data_element : KRB_PA_Data_Element(data_type, pa_data_elem_meta.length);
	} &requires(data_type);
} &let {
	data_type: int64 = binary_to_int64(pa_data_type.data.content);
};

type KRB_PA_Data_Element(type: int64, length: uint64) = case type of {
	1       -> pa_tgs_req		: KRB_AP_REQ;
	3       -> pa_pw_salt		: ASN1OctetString;
	16	-> pa_pk_as_req		: KRB_PA_PK_AS_Req &length=length;
	17	-> pa_pk_as_rep		: KRB_PA_PK_AS_Rep &length=length;
	default -> unknown			: bytestring &length=length;
};

type KRB_PA_PK_AS_Req = record {
	string_meta : ASN1EncodingMeta;
	seq_meta1	: ASN1EncodingMeta;
	elem_0_meta1: ASN1EncodingMeta;
	seq_meta2	: ASN1EncodingMeta;
	oid			: ASN1Encoding;
	elem_0_meta2: ASN1EncodingMeta;
	seq_meta3	: ASN1EncodingMeta;
	version		: ASN1Encoding;
	digest_algs	: ASN1Encoding;
	signed_data	: ASN1Encoding;
	cert_meta	: ASN1EncodingMeta;
	cert		: bytestring &length=cert_meta.length;
	# Ignore everything else
				: bytestring &restofdata &transient;
};

type KRB_PA_PK_AS_Rep = record {
	string_meta : ASN1EncodingMeta;
	elem_0_meta1: ASN1EncodingMeta;
	seq_meta1	: ASN1EncodingMeta;
	elem_0_meta2: ASN1EncodingMeta;
	seq_meta2	: ASN1EncodingMeta;
	oid			: ASN1Encoding;
	elem_0_meta3: ASN1EncodingMeta;
	seq_meta3	: ASN1EncodingMeta;
	version		: ASN1Encoding;
	digest_algs	: ASN1Encoding;
	signed_data	: ASN1Encoding;
	cert_meta	: ASN1EncodingMeta;
	cert		: bytestring &length=cert_meta.length;
	# Ignore everything else
				: bytestring &restofdata &transient;
};

