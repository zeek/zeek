# ASN1 parsing
%include krb-asn1.pac

# Constants
%include krb-defs.pac

# Basic types
%include krb-types.pac

# Preauth data parsing
%include krb-padata.pac

# KRB over TCP is the same as over UDP, but prefixed with a uint32 denoting the size
type KRB_PDU_TCP(is_orig: bool) = record {
	size	: uint32;
	pdu	: KRB_PDU(is_orig);
} &length=size+4 &byteorder=bigendian;

type KRB_PDU(is_orig: bool) = record {
	app_meta  : ASN1EncodingMeta;
	msg_type  : case (app_meta.tag - ASN1_APP_TAG_OFFSET) of {
		AS_REQ    -> as_req   : KRB_AS_REQ(is_orig);
		AS_REP    -> as_rep   : KRB_AS_REP(is_orig);
		TGS_REQ   -> tgs_req  : KRB_TGS_REQ(is_orig);
		TGS_REP   -> tgs_rep  : KRB_TGS_REP(is_orig);
		AP_REQ    -> ap_req   : KRB_AP_REQ(is_orig);
		AP_REP    -> ap_rep   : KRB_AP_REP(is_orig);
		KRB_SAFE  -> krb_safe : KRB_SAFE_MSG(is_orig);
		KRB_PRIV  -> krb_priv : KRB_PRIV_MSG(is_orig);
		KRB_CRED  -> krb_cred : KRB_CRED_MSG(is_orig);
		KRB_ERROR -> krb_error: KRB_ERROR_MSG(is_orig);
	};
} &byteorder=bigendian;

type KRB_AS_REQ(is_orig: bool) = record {
	data: KRB_KDC_REQ(is_orig, AS_REQ);
};

type KRB_TGS_REQ(is_orig: bool) = record {
	data: KRB_KDC_REQ(is_orig, TGS_REQ);
};

type KRB_AS_REP(is_orig: bool) = record {
	data: KRB_KDC_REP(is_orig, AS_REP);
};

type KRB_TGS_REP(is_orig: bool) = record {
	data: KRB_KDC_REP(is_orig, TGS_REP);
};

### A Kerberos ticket-granting-service or authentication-service request

type KRB_KDC_REQ(is_orig: bool, pkt_type: uint8) = record {
	seq_meta   : ASN1EncodingMeta;
	pvno       : SequenceElement(true);
	msg_type   : SequenceElement(true);
	padata	   : KRB_PA_Data_Optional(is_orig, pkt_type, 3);
	body_meta  : ASN1EncodingMeta;
	body_args  : KRB_REQ_Arg[];
};

type KRB_REQ_Arg = record {
	seq_meta   : ASN1EncodingMeta;
	data	   : KRB_REQ_Arg_Data(seq_meta.index) &length=seq_meta.length;
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
	10 	-> auth_data 	: ASN1OctetString;
	11 	-> addl_tkts 	: KRB_Ticket_Sequence;
	default -> unknown	: bytestring &restofdata;
};

type KRB_KDC_Options = record {
	meta	: ASN1EncodingMeta;
	pad	: uint8;
	flags	: uint32;
} &let {
	reserved		: bool	= (flags & 0x80000000) > 0;
	forwardable		: bool	= (flags & 0x40000000) > 0;
	forwarded		: bool	= (flags & 0x20000000) > 0;
	proxiable		: bool	= (flags & 0x10000000) > 0;
	proxy			: bool	= (flags &  0x8000000) > 0;
	allow_postdate		: bool	= (flags &  0x4000000) > 0;
	postdated		: bool	= (flags &  0x2000000) > 0;
	unused7			: bool	= (flags &  0x1000000) > 0;
	renewable		: bool	= (flags &   0x800000) > 0;
	unused9			: bool	= (flags &   0x400000) > 0;
	unused10		: bool	= (flags &   0x200000) > 0;
	opt_hardware_auth	: bool	= (flags &   0x100000) > 0;
	unused12		: bool	= (flags &    0x80000) > 0;
	unused13		: bool	= (flags &    0x40000) > 0;
	# ...
	unused15		: bool	= (flags &    0x10000) > 0;
	# ...
	disable_transited_check	: bool	= (flags &       0x10) > 0;
	renewable_ok		: bool	= (flags &        0x8) > 0;
	enc_tkt_in_skey		: bool	= (flags &        0x4) > 0;
	renew			: bool	= (flags &        0x2) > 0;
	validate		: bool	= (flags &        0x1) > 0;
};

### KDC_REP

type KRB_KDC_REP(is_orig: bool, pkt_type: uint8) = record {
	seq_meta    : ASN1EncodingMeta;
	pvno        : SequenceElement(true);
	msg_type    : SequenceElement(true);
	padata	    : KRB_PA_Data_Optional(is_orig, pkt_type, 2);
	client_realm: ASN1OctetString &length=padata.next_meta.length;
	cname_meta  : ASN1EncodingMeta;
	client_name : KRB_Principal_Name &length=cname_meta.length;
	ticket      : KRB_Ticket(true);
	enc_part    : KRB_Encrypted_Data_in_Seq;
};

### AP_REQ

type KRB_AP_REQ(is_orig: bool) = record {
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
	reserved	: bool = (flags & 0x80000000) > 0;
	use_session_key	: bool = (flags & 0x40000000) > 0;
	mutual_required	: bool = (flags & 0x20000000) > 0;
};


### AP_REP

type KRB_AP_REP(is_orig: bool) = record {
	pvno 	: SequenceElement(true);
	msg_type: SequenceElement(true);
	enc_part: KRB_Encrypted_Data_in_Seq;
};

### KRB_ERROR

type KRB_ERROR_MSG(is_orig: bool) = record {
	seq_meta	: ASN1EncodingMeta;
	args1		: KRB_ERROR_Arg(is_orig, 0)[] &until ($element.process_in_parent);
	error_code	: ASN1Integer;
	args2		: KRB_ERROR_Arg(is_orig, binary_to_int64(error_code.encoding.content))[];
};

type KRB_ERROR_Arg(is_orig: bool, error_code: int64) = record {
	seq_meta: ASN1EncodingMeta;
	args	: KRB_ERROR_Arg_Data(is_orig, seq_meta.index, error_code) &length=arg_length;
} &let {
	process_in_parent : bool = seq_meta.index == 6;
	arg_length 	  : uint64 = ( process_in_parent ? 0 : seq_meta.length);
};

type KRB_ERROR_Arg_Data(is_orig: bool, index: uint8, error_code: int64) = case index of {
	0  -> pvno	: ASN1Integer;
	1  -> msg_type	: ASN1Integer;
	2  -> ctime	: KRB_Time;
	3  -> cusec	: ASN1Integer;
	4  -> stime	: KRB_Time;
	5  -> susec	: ASN1Integer;
	6  -> err_code	: empty;
	7  -> crealm	: ASN1OctetString;
	8  -> cname	: KRB_Principal_Name;
	9  -> realm	: ASN1OctetString;
	10 -> sname	: KRB_Principal_Name;
	11 -> e_text	: ASN1OctetString;
	12 -> e_data	: KRB_ERROR_E_Data(is_orig, error_code);
};

type KRB_ERROR_E_Data(is_orig: bool, error_code: uint64) = case ( error_code == KDC_ERR_PREAUTH_REQUIRED ) of {
	true 	-> padata  : KRB_PA_Data_Sequence(is_orig, KRB_ERROR);
	false	-> unknown : bytestring &restofdata;
};

### KRB_SAFE

type KRB_SAFE_MSG(is_orig: bool) = record {
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

### KRB_PRIV

type KRB_PRIV_MSG(is_orig: bool) = record {
	pvno	: SequenceElement(true);
	msg_type: SequenceElement(true);
	enc_part: KRB_Encrypted_Data_in_Seq;
};

### KRB_CRED

type KRB_CRED_MSG(is_orig: bool) = record {
	pvno	 : SequenceElement(true);
	msg_type : SequenceElement(true);
	tkts_meta: SequenceElement(false);
	tickets  : KRB_Ticket_Sequence;
	enc_part : KRB_Encrypted_Data_in_Seq;
};
