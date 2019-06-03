
# This is the common part in the header format. 
# See RFC 5905 for details
type NTP_PDU(is_orig: bool) = record {
	# The first byte of the NTP header contains the leap indicator,
	# the version and the mode
	first_byte     : uint8;
  	# Modes 1-5 are standard NTP time sync
  	standard_modes  : case (mode>=1 && mode<=5) of {
  		true  	-> std		: NTP_std_msg;
    		false 	-> emp		: empty;
  	};
  	modes_6_7     	: case (mode) of {
		# mode 6 is for control messages (format is different from modes 6-7)
    		6 	-> control 	: NTP_control_msg;
		# mode 7 is reserved or private (and implementation dependent). For example used for some commands such as MONLIST 
    		7 	-> mode7  	: NTP_mode7_msg;
  		default -> unknown	: bytestring &restofdata;
  	};
} &let {
	leap:     uint8  = (first_byte & 0xc0)>>6;   	# First 2 bits of 8-bits value
	version:  uint8  = (first_byte & 0x38)>>3; 	# Bits 3-5 of 8-bits value
	mode:     uint8  = (first_byte & 0x07);  	# Bits 6-8 of 8-bits value
} &byteorder=bigendian &exportsourcedata;

# This is the most common type of message, corresponding to modes 1-5
# This kind of msg are used for normal operation of syncronization
# See RFC 5905 for details
type NTP_std_msg = record {
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
        length          = sourcedata.length();
} &byteorder=bigendian &exportsourcedata;

# This format is for mode==6, control msg
# See RFC 1119 for details
type NTP_control_msg = record {
        second_byte	: uint8;
        sequence	: uint16;
        status      	: uint16;    #TODO: this must be further specified
        association_id	: uint16;
        offs		: uint16;
        c	   	: uint16;
        data		: bytestring &restofdata;
	#auth		: #TODO
} &let {
        R:	bool   = (second_byte & 0x80) > 0;	# First bit of 8-bits value
        E:	bool   = (second_byte & 0x40) > 0;	# Second bit of 8-bits value
        M:     	bool   = (second_byte & 0x20) > 0;	# Third bit of 8-bits value
        OpCode:	uint8  = (second_byte & 0x1F);	# Last 5 bits of 8-bits value
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
