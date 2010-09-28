# $Id:$

enum DNS_answer_type {
	DNS_QUESTION,
	DNS_ANSWER,
	DNS_AUTHORITY,
	DNS_ADDITIONAL,
};

enum DNS_rdata_type {
	TYPE_A		= 1,
	TYPE_NS		= 2,
	TYPE_MD		= 3,
	TYPE_MF		= 4,
	TYPE_CNAME	= 5,
	TYPE_SOA	= 6,
	TYPE_MB		= 7,
	TYPE_MG		= 8,
	TYPE_MR		= 9,
	TYPE_NULL	= 10,
	TYPE_WKS	= 11,
	TYPE_PTR	= 12,
	TYPE_HINFO	= 13,
	TYPE_MINFO	= 14,
	TYPE_MX		= 15,
	TYPE_TXT	= 16,
	TYPE_AAAA	= 28,  # IPv6 (RFC 1886)
	TYPE_NBS	= 32,  # Netbios name (RFC 1002)
	TYPE_A6		= 38,  # IPv6 with indirection (RFC 2874)
	TYPE_EDNS	= 41,  # < OPT pseudo-RR (RFC 2671)
};

#                                    1  1  1  1  1  1
#      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                      ID                       |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                    QDCOUNT                    |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                    ANCOUNT                    |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                    NSCOUNT                    |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                    ARCOUNT                    |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

type DNS_header = record {
	id	: uint16;
	qrop	: uint16;
	qdcount	: uint16;
	ancount	: uint16;
	nscount	: uint16;
	arcount	: uint16;
} &let {
	qr: bool	= qrop >> 15;
	opcode: uint8 	= (qrop >> 11) & 0xf;
	aa: bool 	= (qrop >> 10) & 0x1;
	tc: bool 	= (qrop >> 9) & 0x1;
	rd: bool 	= (qrop >> 8) & 0x1;
	ra: bool 	= (qrop >> 7) & 0x1;
	z: uint8 	= (qrop >> 4) & 0x7;
	rcode: uint8 	= qrop & 0xf;
};

type DNS_label(msg: DNS_message) = record {
	length:		uint8;
	data: 		case label_type of {
		0 ->	label: 	bytestring &length = length;
		3 ->	ptr_lo:	uint8;
	};
} &let {
	label_type: uint8 	= length >> 6;
	last: bool		= (length == 0) || (label_type == 3);

	# A name pointer.
	ptr: DNS_name(msg)
		withinput $context.flow.get_pointer(msg.sourcedata,
			((length & 0x3f) << 8) | ptr_lo)
		&if(label_type == 3);

	clear_pointer_set: bool = $context.flow.reset_pointer_set()
		&if(last);
};

type DNS_name(msg: DNS_message) = record {
	labels:		DNS_label(msg)[] &until($element.last);
};

type DNS_char_string = record {
	length:		uint8;
	data:		bytestring &length = length;
};

#                                    1  1  1  1  1  1
#      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                                               |
#    /                     QNAME                     /
#    /                                               /
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                     QTYPE                     |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                     QCLASS                    |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

type DNS_question(msg: DNS_message) = record {
	qname:	DNS_name(msg);
	qtype:	uint16;
	qclass:	uint16;
};

type DNS_rdata_MX(msg: DNS_message) = record {
	preference:	uint16;
	name:		DNS_name(msg);
};

type DNS_rdata_SOA(msg: DNS_message) = record {
	mname:		DNS_name(msg);
	rname:		DNS_name(msg);
	serial:		uint32;
	refresh:	uint32;
	retry:		uint32;
	expire:		uint32;
	minimum:	uint32;
};

type DNS_rdata_WKS = record {
	address:	uint32;
	protocol:	uint8;
	bitmap:		bytestring &restofdata;
};

type DNS_rdata_HINFO = record {
	cpu:		DNS_char_string;
	os:		DNS_char_string;
};

type DNS_rdata(msg: DNS_message,
		rr_type: uint16,
		rr_class: uint16) = case rr_type of {

	TYPE_A 	   -> type_a: 	  uint32 &check(rr_class == CLASS_IN);
	TYPE_NS    -> type_ns:	  DNS_name(msg);
	TYPE_CNAME -> type_cname: DNS_name(msg);
	TYPE_SOA   -> type_soa:	  DNS_rdata_SOA(msg);
	TYPE_PTR   -> type_ptr:	  DNS_name(msg);
	TYPE_MX    -> type_mx:	  DNS_rdata_MX(msg);
	TYPE_AAAA, TYPE_A6
	           -> type_aaaa:  uint32[4];

	# TYPE_WKS   -> type_wks:   DNS_rdata_WKS;
	# TYPE_HINFO -> type_hinfo: DNS_rdata_HINFO;
	# TYPE_TXT   -> type_txt:   bytestring &restofdata;

	# 3 -> type_md:		DNS_rdata_MD;
	# 4 -> type_mf:		DNS_rdata_MF;
	# 7 -> type_mb:		DNS_rdata_MB;
	# 8 -> type_mg:		DNS_rdata_MG;
	# 9 -> type_mr:		DNS_rdata_MR;
	# 10 -> type_null:	DNS_rdata_NULL;
	# 14 -> type_minfo:	DNS_rdata_MINFO;
	# 32 -> type_nbs:	  DNS_rdata_NBS;

	default -> unknown:	bytestring &restofdata;
};

#                                    1  1  1  1  1  1
#      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                                               |
#    /                                               /
#    /                      NAME                     /
#    |                                               |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                      TYPE                     |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                     CLASS                     |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                      TTL                      |
#    |                                               |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                   RDLENGTH                    |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
#    /                     RDATA                     /
#    /                                               /
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

type DNS_rr(msg: DNS_message, answer_type: DNS_answer_type) = record {
	rr_name:	DNS_name(msg);
	rr_type:	uint16;
	rr_class:	uint16;
	rr_ttl:		uint32;
	rr_rdlength:	uint16;
	rr_rdata:	DNS_rdata(msg, rr_type, rr_class) &length = rr_rdlength;
};

#    +---------------------+
#    |        Header       |
#    +---------------------+
#    |       Question      | the question for the name server
#    +---------------------+
#    |        Answer       | RRs answering the question
#    +---------------------+
#    |      Authority      | RRs pointing toward an authority
#    +---------------------+
#    |      Additional     | RRs holding additional information
#    +---------------------+

type DNS_message = record {
	header:		DNS_header;
	question:	DNS_question(this)[header.qdcount];
	answer:		DNS_rr(this, DNS_ANSWER)[header.ancount];
	authority:	DNS_rr(this, DNS_AUTHORITY)[header.nscount];
	additional:	DNS_rr(this, DNS_ADDITIONAL)[header.arcount];
} &byteorder = bigendian, &exportsourcedata;
