type NTP_PDU(is_orig: bool) = record {
	first_byte     : uint8;
	stratum        : uint8;
	poll           : uint8;
	precision      : uint8;
	
	root_delay     : int32;
	root_dispersion: uint32;
	reference_id   : uint32;
	reference_ts   : uint64;
	
	origin_ts      : uint64;
	receive_ts     : uint64;
	transmit_ts    : uint64;

	extensions     : Extension_Field[] &until($input.length() <= 18);
  have_mac       : case (offsetof(have_mac) < length) of {
  	true  -> mac : NTP_MAC;
    false -> nil : empty;
  } &requires(length);
} &let {
	leap:     bool  = (first_byte & 0xc0); # First 2 bytes of 8-byte value
	leap_61:  bool  = (leap && 0x40) > 0;        # leap_indicator == 1
	leap_59:  bool  = (leap && 0x80) > 0;        # leap_indicator == 2
	leap_unk: bool  = (leap && 0xc0) > 0;        # leap_indicator == 3
	version:  uint8 = (first_byte & 0x38); # Bytes 3-5 of 8-byte value
	mode:     uint8 = (first_byte & 0x7);  # Bytes 6-8 of 8-byte value
  length          = sourcedata.length();
} &byteorder=bigendian &exportsourcedata;

type NTP_MAC = record {
	key_id: uint32;
	digest: bytestring &length=16;
} &length=18;

type Extension_Field = record {
  field_type: uint16;
  length    : uint16;
  data      : bytestring &length=length-4;
};