
type PDU = record {
	identity_byte:    uint8;
	signature_byte:   uint8;
	auth_and_op_crap: uint8;
	next_header:      uint8;
	epoch:            uint32;
	identity:         bytestring &length=identity_len;
	signature:        bytestring &length=signature_len;
	packet:           bytestring &restofdata;
} &let {
	identity_len  = (1 << (identity_byte >> 4));
	signature_len = (signature_byte >> 4) * 4;
} &byteorder = littleendian;