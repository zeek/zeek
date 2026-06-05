# NTP extensions were updated in RFC 7822 to be at least 16 bytes, as well as
# be a multiple of 4. It also has a length field as the second 2 bytes of the
# extension. This function checks whether the length field matches the proper
# values, and is used to check to see if extensions should be parsed.
function ntp_has_extensions(data: bytestring): bool
	%{
	if ( data.length() < 16 )
		return false;

	uint16_t ext_len = (data[2] << 8) | data[3];
	return ext_len >= 16 && ext_len % 4 == 0 && ext_len <= static_cast<uint32_t>(data.length());
	%}

# This is the common part in the header format.
# See RFC 5905 for details
enum NTP_Mode {
	SYMMETRIC_ACTIVE = 1,
	SYMMETRIC_PASSIVE = 2,
	CLIENT = 3,
	SERVER = 4,
	BROADCAST_SERVER = 5,
	BROADCAST_CLIENT = 6,
};

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

	trailing:        bytestring &restofdata;
} &let {
	# Pass the rest of the data to be processed as extension and/or MAC
	ext_and_mac: NTP_Ext_and_MAC(trailing) withinput trailing;
} &byteorder=bigendian;

type NTP_Ext_and_MAC(data: bytestring) = record {
	extensions: case ( has_exts ) of {
		true  -> exts: Extension_Field[] &until($input.length() < 16);
		false -> nil:  empty;
	} &requires(has_exts);

	mac_fields: case ( has_mac ) of {
		true -> mac: NTP_MAC_var(mac_len);
		false -> nil2: empty;
	} &requires(has_mac);
} &let {
	# Check the rest of the data to see if extensions exist
	has_exts: bool = ntp_has_extensions(data);
	mac_len: uint32 = sourcedata.length() - offsetof(mac_fields);
	has_mac: bool = mac_len >= 4;
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

# As in RFC 5905, variable-length MAC: 4-byte key ID + variable-length digest
type NTP_MAC_var(total_len: uint32) = record {
	key_id: uint32;
	digest: bytestring &length=(total_len - 4);
};

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
