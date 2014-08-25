%include krb-asn1.pac

enum KRBMessageTypes {
	AS_REQ    = 10,
	AS_REP    = 11,
	TGS_REQ   = 12,
	TGS_REP   = 13,
	AP_REQ    = 14,
	AP_REP    = 15,
	KRB_SAFE  = 20,
	KRB_PRIV  = 21,
	KRB_CRED  = 22,
	KRB_ERROR = 30,
};

type KRB_PDU = record {
	app_meta  : ASN1EncodingMeta;
	msg_type  : case (app_meta.tag - 96) of {
		AS_REQ    -> as_req   : KRB_AS_REQ;
		AS_REP    -> as_rep   : KRB_AS_REP;
		TGS_REQ   -> tgs_req  : KRB_TGS_REQ;
		TGS_REP   -> tgs_rep  : KRB_TGS_REP;
		AP_REQ    -> ap_req   : KRB_AP_REQ;
		AP_REP    -> ap_rep   : KRB_AP_REP;
		KRB_SAFE  -> krb_safe : KRB_SAFE_MSG;
		KRB_PRIV  -> krb_priv : KRB_PRIV_MSG;
		KRB_CRED  -> krb_cred : KRB_CRED_MSG;
		KRB_ERROR -> krb_error: KRB_ERROR_MSG;
		default   -> unknown  : bytestring &restofdata;
	};
} &byteorder=bigendian;

type KRB_AS_REQ = record {
	data: KRB_KDC_REQ;
};

type KRB_TGS_REQ = record {
	data: KRB_KDC_REQ;
};

type KRB_AS_REP = record {
	data: KRB_KDC_REP;
};

type KRB_TGS_REP = record {
	data: KRB_KDC_REP;
};

### KDC_REQ

type KRB_KDC_REQ = record {
	seq_meta   : ASN1EncodingMeta;
	pvno       : SequenceElement(true);
	msg_type   : SequenceElement(true);
	padata_meta: ASN1EncodingMeta;
	tmp1       : case has_padata of {
		true  -> padata	: KRB_PA_Data_Sequence &length=padata_meta.length;
		false -> n1	: empty;
	};
	tmp2       : case has_padata of {
		true  -> meta2	: ASN1EncodingMeta;
		false -> n2		: empty;
	};
	body       : KRB_REQ_Body &length=body_length;
} &let {
	has_padata : bool = padata_meta.index == 3;
	body_length: uint8 = has_padata ? meta2.length : padata_meta.length;
};

type KRB_PA_Data_Sequence = record {
	seq_meta    : ASN1EncodingMeta;
	padata_elems: KRB_PA_Data[];
};

type KRB_PA_Data = record {
	seq_meta		: ASN1EncodingMeta;
	pa_data_type     	: SequenceElement(true);
	pa_data_elem_meta	: ASN1EncodingMeta;
	pa_data_element  	: KRB_PA_Data_Element(data_type);
} &let {
	data_type: int64 = binary_to_int64(pa_data_type.data.content);
};

type KRB_PA_Data_Element(type: int64) = case type of {
	1       -> pa_tgs_req		: KRB_AP_REQ;
	2       -> pa_enc_timestamp	: KRB_Encrypted_Data;
	3       -> pa_pw_salt		: ASN1OctetString;
	default -> unknown		: bytestring &restofdata;
};

type KRB_REQ_Body = record {
	seq_meta	: ASN1EncodingMeta;
	args		: KRB_REQ_Arg[];
};

type KRB_REQ_Arg = record {
	seq_meta	: ASN1EncodingMeta;
	data		: KRB_REQ_Arg_Data(seq_meta.index) &length=seq_meta.length;
};

type KRB_REQ_Arg_Data(index: uint8) = case index of {
	0 	-> options	: KRB_KDC_Options;
	1  	-> principal	: KRB_Principal_Name;
	2  	-> realm	: ASN1OctetString;
	3  	-> sname	: KRB_Principal_Name;
	4  	-> from		: KRB_Time;
	5  	-> till		: KRB_Time;
	6  	-> rtime	: KRB_Time;
	7  	-> nonce	: ASN1Integer;
	8  	-> etype	: Array;
	9  	-> addrs	: KRB_Host_Addresses;
	10 	-> auth_data 	: ASN1OctetString; # TODO
	11 	-> addl_tkts 	: KRB_Ticket_Sequence;
	default -> unknown	: bytestring &restofdata;
};

type KRB_KDC_Options = record {
	meta : ASN1EncodingMeta;
	flags: uint32;
} &let {
	reserved		: bool	= flags & 0x80000000;
	forwardable		: bool	= flags & 0x40000000;
	forwarded		: bool	= flags & 0x20000000;
	proxiable		: bool	= flags & 0x10000000;
	proxy			: bool	= flags &  0x8000000;
	allow_postdate		: bool	= flags &  0x4000000;
	postdated		: bool	= flags &  0x2000000;
	unused7			: bool	= flags &  0x1000000;
	renewable		: bool	= flags &   0x800000;
	unused9			: bool	= flags &   0x400000;
	unused10		: bool	= flags &   0x200000;
	opt_hardware_auth	: bool	= flags &   0x100000;
	unused12		: bool	= flags &    0x80000;
	unused13		: bool	= flags &    0x40000;
	# ...
	unused15		: bool	= flags &    0x10000;
	# ...
	disable_transited_check	: bool	= flags &       0x10;
	renewable_ok		: bool	= flags &        0x8;
	enc_tkt_in_skey		: bool	= flags &        0x4;
	renew			: bool	= flags &        0x2;
	validate		: bool	= flags &        0x1;
};

type KRB_Principal_Name = record {
	seq_meta  : ASN1EncodingMeta;
	name_meta : ASN1EncodingMeta;
	name_type : ASN1Integer;
	seq_meta_1: ASN1EncodingMeta;
	seq_meta_2: ASN1EncodingMeta;
	data      : ASN1OctetString[] &length=seq_meta_2.length;
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
	addr_type: SequenceElement(true);
	address  : SequenceElement(true);
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
	sname	  : KRB_Principal_Name;
	enc_part  : KRB_Encrypted_Data;
};

type KRB_Ticket_Sequence = record {
	seq_meta : ASN1EncodingMeta;
	tickets  : KRB_Ticket(true)[] &length=seq_meta.length;
};

type KRB_Encrypted_Data_in_Seq = record {
	index_meta  : ASN1EncodingMeta;
	data	    : KRB_Encrypted_Data;
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

### KDC_REP

type KRB_KDC_REP = record {
	seq_meta    : ASN1EncodingMeta;
	pvno        : SequenceElement(true);
	msg_type    : SequenceElement(true);
	padata_meta : ASN1EncodingMeta;
	tmp1        : case has_padata of {
		true -> padata	: KRB_PA_Data_Sequence &length=padata_meta.length;
		false -> n1	: empty;
	};
	tmp2        : case has_padata of {
		true -> meta2	: ASN1EncodingMeta;
		false -> n2	: empty;
	};
	client_realm: ASN1OctetString &length=realm_length;
	client_name : KRB_Principal_Name;
	ticket      : KRB_Ticket(true);
	enc_part    : KRB_Encrypted_Data_in_Seq;
} &let {
	has_padata  : bool = padata_meta.index == 2;
	realm_length: uint8 = has_padata ? meta2.length : padata_meta.length;
};

### AP_REQ

type KRB_AP_REQ = record {
	string_meta : ASN1EncodingMeta;
	app_meta    : ASN1EncodingMeta;
	seq_meta    : ASN1EncodingMeta;
	pvno 	    : SequenceElement(true);
	msg_type    : SequenceElement(true);
	ap_options  : KRB_AP_Options;
	ticket	    : KRB_Ticket(true);
	enc_part    : KRB_Encrypted_Data_in_Seq;
};

type KRB_AP_Options = record {
	meta 	: SequenceElement(false);
	flags	: uint32;
		: padding[1];
} &let {
	reserved	: bool = flags & 0x80000000;
	use_session_key	: bool = flags & 0x40000000;
	mutual_required	: bool = flags & 0x20000000;
};


### AP_REP

type KRB_AP_REP = record {
	pvno 	: SequenceElement(true);
	msg_type: SequenceElement(true);
	enc_part: KRB_Encrypted_Data_in_Seq;
};

### KRB_ERROR

type KRB_ERROR_MSG = record {
	seq_meta: ASN1EncodingMeta;
	args	: KRB_ERROR_Arg[];
};

type KRB_ERROR_Arg = record {
	seq_meta: ASN1EncodingMeta;
	args	: KRB_ERROR_Arg_Data(seq_meta.index) &length=seq_meta.length;
};

type KRB_ERROR_Arg_Data(index: uint8) = case index of {
	0  -> pvno		: ASN1Integer;
	1  -> msg_type		: ASN1Integer;
	2  -> ctime		: KRB_Time;
	3  -> cusec		: ASN1Integer;
	4  -> stime		: KRB_Time;
	5  -> susec		: ASN1Integer;
	6  -> error_code	: ASN1Integer;
	7  -> crealm		: ASN1OctetString;
	8  -> cname		: KRB_Principal_Name;
	9  -> realm		: ASN1OctetString;
	10 -> sname		: KRB_Principal_Name;
	11 -> e_text		: ASN1OctetString;
	12 -> e_data		: ASN1OctetString;
};

### KRB_SAFE

type KRB_SAFE_MSG = record {
	pvno	 : SequenceElement(true);
	msg_type : SequenceElement(true);
	safe_body: KRB_SAFE_Body;
	checksum : KRB_Checksum;
};

type KRB_SAFE_Body = record {
	seq_meta: ASN1EncodingMeta;
	args	: KRB_SAFE_Arg[];
};

type KRB_SAFE_Arg = record {
	seq_meta: ASN1EncodingMeta;
	args    : KRB_SAFE_Arg_Data(seq_meta.index) &length=seq_meta.length;
};

type KRB_SAFE_Arg_Data(index: uint8) = case index of {
	0 -> user_data	: ASN1OctetString;
	1 -> timestamp  : KRB_Time;
	2 -> usec	: ASN1Integer;
	3 -> seq_number : ASN1Integer;
	4 -> sender_addr: KRB_Host_Address;
	5 -> recp_addr  : KRB_Host_Address;
};

type KRB_Checksum = record {
	checksum_type: SequenceElement(true);
	checksum     : SequenceElement(true);
};

### KRB_PRIV

type KRB_PRIV_MSG = record {
	pvno	: SequenceElement(true);
	msg_type: SequenceElement(true);
	enc_part: KRB_Encrypted_Data_in_Seq;
};

### KRB_CRED

type KRB_CRED_MSG = record {
	pvno	 : SequenceElement(true);
	msg_type : SequenceElement(true);
	tkts_meta: SequenceElement(false);
	tickets  : KRB_Ticket_Sequence;
	enc_part : KRB_Encrypted_Data_in_Seq;
};