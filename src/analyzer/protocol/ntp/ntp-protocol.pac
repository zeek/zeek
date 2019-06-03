type NTP_PDU(is_orig: bool) = record {
	first_byte : uint8;

	# Modes 1-5 are standard NTP time sync
	mode_chk_1 : case (mode>=1 && mode<=5) of {
  		true  -> msg: NTP_Association(first_byte, mode, version);
		false -> unk: empty;
	} &requires(version);

	mode_chk_2 : case (mode) of {
		6 -> ctl_msg       : NTP_Mode6(first_byte, version) &restofdata;
		7 -> mode_7        : NTP_Mode7(first_byte, version) &restofdata;
		default -> unknown: bytestring &restofdata;
	} &requires(version);

} &let {
	mode:    uint8 = (first_byte & 0x7);       # Bytes 6-8 of 8-byte value
	version: uint8 = (first_byte & 0x38) >> 3; # Bytes 3-5 of 8-byte value
} &byteorder=bigendian;

type NTP_Association(first_byte: uint8, mode: uint8, version: uint8) = record {
	stratum        : uint8;
	poll           : int8;
	precision      : int8;
	
	root_delay     : NTP_Short_Time;
	root_dispersion: NTP_Short_Time;
	reference_id   : bytestring &length=4;
	reference_ts   : NTP_Time;
	
	origin_ts      : NTP_Time;
	receive_ts     : NTP_Time;
	transmit_ts    : NTP_Time;

	extensions     : Extension_Field[] &until($input.length() <= 18);
	have_mac       : case (offsetof(have_mac) < length) of {
		true  -> mac : NTP_MAC;
		false -> nil : empty;
	} &requires(length);
} &let {
	leap:     bool  = (first_byte & 0xc0); # First 2 bytes of 8-byte value
	leap_61:  bool  = (leap & 0x40) > 0;   # leap_indicator == 1
	leap_59:  bool  = (leap & 0x80) > 0;   # leap_indicator == 2
	leap_unk: bool  = (leap & 0xc0) > 0;   # leap_indicator == 3
	length          = sourcedata.length();
} &exportsourcedata;

type NTP_MAC = record {
	key_id: uint32;
	digest: bytestring &length=16;
} &length=18;

type Extension_Field = record {
	field_type: uint16;
	length    : uint16;
	data      : bytestring &length=length-4;
};

type NTP_Short_Time = record {
	seconds:   int16;
	fractions: int16;
};

type NTP_Time = record {
	seconds:   uint32;
	fractions: uint32;
};


# From RFC 1305, Appendix B:
type NTP_Mode6(first_byte: uint8, version: uint8) = record {
	rem_op  : uint8;
	sequence: uint16;
	status  : uint16;
	assoc_id: uint16;
	offset  : uint16;
	count   : uint16;
	data    : bytestring &length=count;
	pad     : padding[pad_length];
	opt_auth: bytestring &restofdata;
} &let {
	response_bit: bool = (rem_op & 0x80) > 0;
	error_bit   : bool = (rem_op & 0x40) > 0;
	more_bit    : bool = (rem_op & 0x20) > 0;
	opcode      : uint8 = (rem_op & 0x1f);
	pad_length  : uint8 = (count % 32 == 0) ? 0 : 32 - (count % 32);
};
