type RDPEUDP_PDU(is_orig: bool) = record {
	data: bytestring &restofdata;
} &byteorder=bigendian;
