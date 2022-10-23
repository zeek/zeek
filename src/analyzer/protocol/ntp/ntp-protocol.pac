# This is the common part in the header format.
# See RFC 5905 for details
type NTP_PDU(is_orig: bool) = record {
	# The first byte of the NTP header contains the leap indicator,
	# the version and the mode
	first_byte: uint8;

	# Modes 1-5 are standard NTP time sync
	standard_modes: case ( mode >= 1 && mode <=5 ) of {
		true    -> std        : NTP_std_msg;
		false   -> emp        : empty;
	};

	modes_6_7: case ( mode ) of {
		# Mode 6 is for control messages (format is different from modes 6-7)
		6 -> control:      NTP_control_msg;
		# Mode 7 is reserved or private (and implementation dependent).
		# For example used for some commands such as MONLIST
		7 -> mode7:        NTP_mode7_msg;
		default -> unknown: bytestring &restofdata;
	};
} &let {
	leap:    uint8 = (first_byte & 0xc0)>>6;  # First 2 bits of 8-bits value
	version: uint8 = (first_byte & 0x38)>>3;  # Bits 3-5 of 8-bits value
	mode:    uint8 = (first_byte & 0x07);     # Bits 6-8 of 8-bits value
} &byteorder=bigendian &exportsourcedata;

# This is the most common type of message, corresponding to modes 1-5
# This kind of msg are used for normal operation of synchronization
# See RFC 5905 for details
type NTP_std_msg = record {
	stratum:   uint8;
	poll:      int8;
	precision: int8;

	root_delay:      NTP_Short_Time;
	root_dispersion: NTP_Short_Time;

	reference_id:    bytestring &length=4;
	reference_ts:    NTP_Time;

	origin_ts:       NTP_Time;
	receive_ts:      NTP_Time;
	transmit_ts:     NTP_Time;

	extensions: case ( has_exts ) of {
		true  -> exts: Extension_Field[] &until($input.length() <= 24);
		false -> nil:  empty;
	} &requires(has_exts);

	mac_fields: case ( mac_len ) of {
		20 -> mac: NTP_MAC;
		24 -> mac_ext: NTP_MAC_ext;
		default -> nil2: empty;
	} &requires(mac_len);
} &let {
	length = sourcedata.length();
	has_exts: bool = (length - offsetof(extensions)) > 24;
	mac_len: uint32 = (length - offsetof(mac_fields));
} &byteorder=bigendian &exportsourcedata;

# This format is for mode==6, control msg
# See RFC 1119 for details
type NTP_control_msg = record {
	second_byte:     uint8;
	sequence:        uint16;
	status:          uint16; #TODO: this can be further parsed internally
	association_id:  uint16;
	offs:            uint16;
	c:               uint16;
	data:            bytestring &length=c;

	mac_fields: case ( has_control_mac ) of {
		true -> mac:  NTP_CONTROL_MAC;
		false -> nil: empty;
	} &requires(has_control_mac);
} &let {
	R: bool = (second_byte & 0x80) > 0; # First bit of 8-bits value
	E: bool = (second_byte & 0x40) > 0; # Second bit of 8-bits value
	M: bool = (second_byte & 0x20) > 0; # Third bit of 8-bits value
	OpCode: uint8 = (second_byte & 0x1F); # Last 5 bits of 8-bits value
	length = sourcedata.length();
	has_control_mac: bool = (length - offsetof(mac_fields)) == 12;
} &byteorder=bigendian &exportsourcedata;

# As in RFC 5905
type NTP_MAC = record {
	key_id: uint32;
	digest: bytestring &length=16;
} &length=20;

# As in RFC 5906, same as NTP_MAC but with a 160 bit digest
type NTP_MAC_ext = record {
	key_id: uint32;
	digest: bytestring &length=20;
} &length=24;

# As in RFC 1119
type NTP_CONTROL_MAC = record {
	key_id: uint32;
	crypto_checksum: bytestring &length=8;
} &length=12;

# As defined in RFC 5906
type Extension_Field = record {
	first_byte_ext: uint8;
	field_type:     uint8;
	len:            uint16;
	association_id: uint16;
	timestamp:      uint32;
	filestamp:      uint32;
	value_len:      uint32;
	value:          bytestring &length=value_len;
	sig_len:        uint32;
	signature:      bytestring &length=sig_len;
	pad:            padding to (len - offsetof(first_byte_ext));
} &let {
	R:    bool  = (first_byte_ext & 0x80) > 0; # First bit of 8-bits value
	E:    bool  = (first_byte_ext & 0x40) > 0; # Second bit of 8-bits value
	Code: uint8 = (first_byte_ext & 0x3F); # Last 6 bits of 8-bits value
};

type NTP_Short_Time = record {
	seconds: int16;
	fractions: int16;
};

type NTP_Time = record {
	seconds: uint32;
	fractions: uint32;
};
