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

type KRB_PDU_TCP = record {
	size: uint32;
	pdu	: KRB_PDU;
} &length=size+4 &byteorder=bigendian;

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
		false -> n1		: empty;
	};
	tmp2       : case has_padata of {
		true  -> meta2	: ASN1EncodingMeta;
		false -> n2		: empty;
	};
	body       : KRB_REQ_Body &length=body_length;
} &let {
	has_padata : bool = padata_meta.index == 3;
	body_length: uint64 = has_padata ? meta2.length : padata_meta.length;
};

type KRB_PA_Data_Sequence = record {
	seq_meta    : ASN1EncodingMeta;
	padata_elems: KRB_PA_Data[];
};

type KRB_PA_Data = record {
	seq_meta			: ASN1EncodingMeta;
	pa_data_type     	: SequenceElement(true);
	pa_data_elem_meta	: ASN1EncodingMeta;
	pa_data_element  	: KRB_PA_Data_Element(data_type, pa_data_elem_meta.length);
} &let {
	data_type: int64 = binary_to_int64(pa_data_type.data.content);
};

type KRB_PA_Data_Element(type: int64, length: uint64) = case type of {
	1       -> pa_tgs_req		: KRB_AP_REQ;
	3       -> pa_pw_salt		: ASN1OctetString;
	default -> unknown			: bytestring &length=length;
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
 	0 	-> options		: KRB_KDC_Options;
 	1  	-> principal	: KRB_Principal_Name;
 	2  	-> realm		: ASN1OctetString;
 	3  	-> sname		: KRB_Principal_Name;
 	4  	-> from			: KRB_Time;
 	5  	-> till			: KRB_Time;
 	6  	-> rtime		: KRB_Time;
 	7  	-> nonce		: ASN1Integer;
 	8  	-> etype		: Array;
 	9  	-> addrs		: KRB_Host_Addresses;
 	10 	-> auth_data 	: ASN1OctetString; # TODO
 	11 	-> addl_tkts 	: KRB_Ticket_Sequence;
	default -> unknown	: bytestring &restofdata;
};

type KRB_KDC_Options = record {
	meta : ASN1EncodingMeta;
	pad: uint8;
	flags: uint32;
} &let {
	reserved				: bool	= (flags & 0x80000000) > 0;
	forwardable				: bool	= (flags & 0x40000000) > 0;
	forwarded				: bool	= (flags & 0x20000000) > 0;
	proxiable				: bool	= (flags & 0x10000000) > 0;
	proxy					: bool	= (flags &  0x8000000) > 0;
	allow_postdate			: bool	= (flags &  0x4000000) > 0;
	postdated				: bool	= (flags &  0x2000000) > 0;
	unused7					: bool	= (flags &  0x1000000) > 0;
	renewable				: bool	= (flags &   0x800000) > 0;
	unused9					: bool	= (flags &   0x400000) > 0;
	unused10				: bool	= (flags &   0x200000) > 0;
	opt_hardware_auth		: bool	= (flags &   0x100000) > 0;
	unused12				: bool	= (flags &    0x80000) > 0;
	unused13				: bool	= (flags &    0x40000) > 0;
	# ...
	unused15				: bool	= (flags &    0x10000) > 0;
	# ...
	disable_transited_check	: bool	= (flags &       0x10) > 0;
	renewable_ok			: bool	= (flags &        0x8) > 0;
	enc_tkt_in_skey			: bool	= (flags &        0x4) > 0;
	renew					: bool	= (flags &        0x2) > 0;
	validate				: bool	= (flags &        0x1) > 0;
};

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
	addr_type		: ASN1Integer;
	address  		: SequenceElement(true);
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
	cname_meta	: ASN1EncodingMeta;
	client_name : KRB_Principal_Name &length=cname_meta.length;
	ticket      : KRB_Ticket(true);
	enc_part    : KRB_Encrypted_Data_in_Seq;
} &let {
	has_padata  : bool = padata_meta.index == 2;
	realm_length: uint64 = has_padata ? meta2.length : padata_meta.length;
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
	reserved		: bool = (flags & 0x80000000) > 0;
	use_session_key	: bool = (flags & 0x40000000) > 0;
	mutual_required	: bool = (flags & 0x20000000) > 0;
};


### AP_REP

type KRB_AP_REP = record {
	pvno 	: SequenceElement(true);
	msg_type: SequenceElement(true);
	enc_part: KRB_Encrypted_Data_in_Seq;
};

### KRB_ERROR

# pvno            [0] INTEGER (5),
# msg-type        [1] INTEGER (30),
# ctime           [2] KerberosTime OPTIONAL,
# cusec           [3] Microseconds OPTIONAL,
# stime           [4] KerberosTime,
# susec           [5] Microseconds,
# error-code      [6] Int32,
# crealm          [7] Realm OPTIONAL,
# cname           [8] PrincipalName OPTIONAL,
# realm           [9] Realm -- service realm --,
# sname           [10] PrincipalName -- service name --,
# e-text          [11] KerberosString OPTIONAL,

type KRB_ERROR_MSG = record {
	seq_meta	: ASN1EncodingMeta;
 	pvno		: SequenceElement(true);
 	msg_type	: SequenceElement(true);
 	ctime_meta	: ASN1EncodingMeta;
 	tmp1		: case has_ctime of {
 		true  	-> ctime 	: bytestring &length=ctime_meta.length;
 		false 	-> n1	   	: empty;
 	};
 	tmp2		: case has_ctime of {
 		true	-> cusec_meta	: ASN1EncodingMeta;
 		false	-> n2			: empty;
 	};
 	tmp3		: case has_cusec of {
 		true	-> cusec	: ASN1Integer;
 		false	-> n3		: empty;
 	};
 	tmp4		: case has_cusec of {
 		true	-> stime_meta	: ASN1EncodingMeta;
 		false	-> n4			: empty;
 	};
	stime		: bytestring &length=stime_length;
	susec		: SequenceElement(true);
	error_code	: SequenceElement(true);
	args		: KRB_ERROR_Arg(binary_to_int64(error_code.data.content))[];
} &let {
 	has_ctime: bool = ctime_meta.index == 2;
 	has_cusec: bool = has_ctime ? cusec_meta.index == 3 : ctime_meta.index == 3;
	stime_length: uint64 = has_ctime ? (has_cusec ? stime_meta.length : cusec_meta.length) : (has_cusec ? stime_meta.length : ctime_meta.length);
};

type KRB_ERROR_Arg(error_code: uint64) = record {
	seq_meta: ASN1EncodingMeta;
	args	: KRB_ERROR_Arg_Data(seq_meta.index, error_code) &length=seq_meta.length;
};

type KRB_ERROR_Arg_Data(index: uint8, error_code: uint64) = case index of {
	7  -> crealm		: ASN1OctetString;
	8  -> cname			: KRB_Principal_Name;
	9  -> realm			: ASN1OctetString;
	10 -> sname			: KRB_Principal_Name;
	11 -> e_text		: ASN1OctetString;
	12 -> e_data		: KRB_ERROR_PA_Data(error_code);
};

type KRB_ERROR_PA_Data(error_code: uint64) = record {
	have_padata1: case ( error_code == 25 ) of {
		true 	-> meta1 	: ASN1EncodingMeta;
		false	-> data		: ASN1OctetString;
	};
	have_padata2: case ( error_code == 25 ) of {
		true 	-> padata 	: KRB_PA_Data_Sequence;
		false	-> n1		: empty;
	};
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
	2 -> usec		: ASN1Integer;
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