##! Types, errors, and fields for analyzing DNS data.  A helper file
##! for DNS analysis scripts.

module DNS;

export {
	const PTR = 12;  ##< RR TYPE value for a domain name pointer.
	const EDNS = 41; ##< An OPT RR TYPE value described by EDNS.
	const ANY = 255; ##< A QTYPE value describing a request for all records.

	## Mapping of DNS query type codes to human readable string
	## representation.
	const query_types = {
		[1] = "A",
		[2] = "NS",
		[3] = "MD",
		[4] = "MF",
		[5] = "CNAME",
		[6] = "SOA",
		[7] = "MB",
		[8] = "MG",
		[9] = "MR",
		[10] = "NULL",
		[11] = "WKS",
		[12] = "PTR",
		[13] = "HINFO",
		[14] = "MINFO",
		[15] = "MX",
		[16] = "TXT",
		[17] = "RP",
		[18] = "AFSDB",
		[19] = "X25",
		[20] = "ISDN",
		[21] = "RT",
		[22] = "NSAP",
		[23] = "NSAP-PTR",
		[24] = "SIG",
		[25] = "KEY",
		[26] = "PX" ,
		[27] = "GPOS",
		[28] = "AAAA",
		[29] = "LOC",
		[30] = "NXT",
		[31] = "EID",
		[32] = "NIMLOC",
		[33] = "SRV",
		[34] = "ATMA",
		[35] = "NAPTR",
		[36] = "KX",
		[37] = "CERT",
		[38] = "A6",
		[39] = "DNAME",
		[40] = "SINK",
		[41] = "OPT",
		[42] = "APL",
		[43] = "DS",
		[44] = "SSHFP",
		[45] = "IPSECKEY",
		[46] = "RRSIG",
		[47] = "NSEC",
		[48] = "DNSKEY",
		[49] = "DHCID",
		[50] = "NSEC3",
		[51] = "NSEC3PARAM",
		[52] = "TLSA",
		[53] = "SMIMEA",
		[55] = "HIP",
		[56] = "NINFO",
		[57] = "RKEY",
		[58] = "TALINK",
		[59] = "CDS",
		[60] = "CDNSKEY",
		[61] = "OPENPGPKEY",
		[62] = "CSYNC",
		[63] = "ZONEMD",
		[64] = "SVCB",
		[65] = "HTTPS",
		[99] = "SPF",
		[100] = "UINFO",
		[101] = "UID",
		[102] = "GID",
		[103] = "UNSPEC",
		[104] = "NID",
		[105] = "L32",
		[106] = "L64",
		[107] = "LP",
		[108] = "EUI48",
		[109] = "EUI64",
		[249] = "TKEY",
		[250] = "TSIG",
		[251] = "IXFR",
		[252] = "AXFR",
		[253] = "MAILB",
		[254] = "MAILA",
		[255] = "*",
		[256] = "URI",
		[257] = "CAA",
		[32768] = "TA",
		[32769] = "DLV",
		[65281] = "WINS",
		[65282] = "WINS-R",
		[65422] = "XPF",
		[65521] = "INTEGRITY", # google: https://docs.google.com/document/d/14eCqVyT_3MSj7ydqNFl1Yl0yg1fs6g24qmYUUdi5V-k/edit
	} &default = function(n: count): string { return fmt("query-%d", n); };

	## Errors used for non-TSIG/EDNS types.
	const base_errors = {
		[0] = "NOERROR",        # No Error
		[1] = "FORMERR",        # Format Error
		[2] = "SERVFAIL",       # Server Failure
		[3] = "NXDOMAIN",       # Non-Existent Domain
		[4] = "NOTIMP",         # Not Implemented
		[5] = "REFUSED",        # Query Refused
		[6] = "YXDOMAIN",       # Name Exists when it should not
		[7] = "YXRRSET",        # RR Set Exists when it should not
		[8] = "NXRRSet",        # RR Set that should exist does not
		[9] = "NOTAUTH",        # Server Not Authoritative for zone
		[10] = "NOTZONE",       # Name not contained in zone
		[11] = "unassigned-11", # available for assignment
		[12] = "unassigned-12", # available for assignment
		[13] = "unassigned-13", # available for assignment
		[14] = "unassigned-14", # available for assignment
		[15] = "unassigned-15", # available for assignment
		[16] = "BADVERS",       # for EDNS, collision w/ TSIG
		[17] = "BADKEY",        # Key not recognized
		[18] = "BADTIME",       # Signature out of time window
		[19] = "BADMODE",       # Bad TKEY Mode
		[20] = "BADNAME",       # Duplicate key name
		[21] = "BADALG",        # Algorithm not supported
		[22] = "BADTRUNC",      # draft-ietf-dnsext-tsig-sha-05.txt
		[23] = "BADCOOKIE",     # Bad EDNS cookie value
		[3842] = "BADSIG",      # 16 <= number collision with EDNS(16);
		                        # this is a translation from TSIG(16)
	} &default = function(n: count): string { return fmt("rcode-%d", n); };

	## This deciphers EDNS Z field values.
	const edns_zfield = {
		[0]     = "NOVALUE",    # regular entry
		[32768] = "DNS_SEC_OK", # accepts DNS Sec RRs
	} &default="?";

	## Possible values of the CLASS field in resource records or QCLASS
	## field in query messages.
	const classes = {
		[1]   = "C_INTERNET",
		[2]   = "C_CSNET",
		[3]   = "C_CHAOS",
		[4]   = "C_HESIOD",
		[254] = "C_NONE",
		[255] = "C_ANY",
	} &default = function(n: count): string { return fmt("qclass-%d", n); };

	## Possible values of the algorithms used in DNSKEY, DS and RRSIG records
	const algorithms = {
		[0] = "reserved0",
		[1] = "RSA_MD5",
		[2] = "Diffie_Hellman",
		[3] = "DSA_SHA1",
		[4] = "Elliptic_Curve",
		[5] = "RSA_SHA1",
		[6] = "DSA_NSEC3_SHA1",
		[7] = "RSA_SHA1_NSEC3_SHA1",
		[8] = "RSA_SHA256",
		[10] = "RSA_SHA512",
		[12] = "GOST_R_34_10_2001",
		[13] = "ECDSA_curveP256withSHA256",
		[14] = "ECDSA_curveP384withSHA384",
		[15] = "Ed25519",
		[16] = "Ed448",
		[252] = "Indirect",
		[253] = "PrivateDNS",
		[254] = "PrivateOID",
		[255] = "reserved255",
	} &default = function(n: count): string { return fmt("algorithm-%d", n); };

	## Possible digest types used in DNSSEC.
	const digests = {
		[0] = "reserved0",
		[1] = "SHA1",
		[2] = "SHA256",
		[3] = "GOST_R_34_11_94",
		[4] = "SHA384",
	} &default = function(n: count): string { return fmt("digest-%d", n); };

	## SVCB/HTTPS SvcParam keys, as defined in
	## https://www.ietf.org/archive/id/draft-ietf-dnsop-svcb-https-07.txt, sec 14.3.2
	const svcparam_keys = {
		[0] = "mandatory",
		[1] = "alpn",
		[2] = "no-default-alpn",
		[3] = "port",
		[4] = "ipv4hint",
		[5] = "ech",
		[6] = "ipv6hint",
	} &default = function(n: count): string { return fmt("key-%d", n); };
}
