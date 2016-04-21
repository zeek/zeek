type NTP_PDU(is_orig: bool) = record {
	first_byte     : uint8;
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
	leap_61:  bool  = (leap && 0x40) > 0;        # leap_indicator == 1
	leap_59:  bool  = (leap && 0x80) > 0;        # leap_indicator == 2
	leap_unk: bool  = (leap && 0xc0) > 0;        # leap_indicator == 3
	version:  uint8 = (first_byte & 0x38) >> 3; # Bytes 3-5 of 8-byte value
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

type NTP_Short_Time = record {
  seconds:   int16;
  fractions: int16;
};

type NTP_Time = record {
  seconds:   uint32;
  fractions: uint32;
};