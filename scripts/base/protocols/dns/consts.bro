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
		[1] = "A", [2] = "NS", [3] = "MD", [4] = "MF",
		[5] = "CNAME", [6] = "SOA", [7] = "MB", [8] = "MG",
		[9] = "MR", [10] = "NULL", [11] = "WKS", [PTR] = "PTR",
		[13] = "HINFO", [14] = "MINFO", [15] = "MX", [16] = "TXT",
		[17] = "RP", [18] = "AFSDB", [19] = "X25", [20] = "ISDN",
		[21] = "RT", [22] = "NSAP", [23] = "NSAP-PTR", [24] = "SIG",
		[25] = "KEY", [26] = "PX" , [27] = "GPOS", [28] = "AAAA",
		[29] = "LOC", [30] = "EID", [31] = "NIMLOC", [32] = "NB",
		[33] = "SRV", [34] = "ATMA", [35] = "NAPTR", [36] = "KX",
		[37] = "CERT", [38] = "A6", [39] = "DNAME", [40] = "SINK",
	 	[EDNS] = "EDNS", [42] = "APL", [43] = "DS", [44] = "SINK",
		[45] = "SSHFP", [46] = "RRSIG", [47] = "NSEC", [48] = "DNSKEY",
		[49] = "DHCID", [99] = "SPF", [100] = "DINFO", [101] = "UID",
		[102] = "GID", [103] = "UNSPEC", [249] = "TKEY", [250] = "TSIG",
		[251] = "IXFR", [252] = "AXFR", [253] = "MAILB", [254] = "MAILA",
		[32768] = "TA", [32769] = "DLV",
		[ANY] = "*",
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
		[4]   = "C_HESOD",
		[254] = "C_NONE",
		[255] = "C_ANY",
	} &default = function(n: count): string { return fmt("qclass-%d", n); };
}
