type SOCKS_Message(is_orig: bool) = case is_orig of {
	true ->  request: SOCKS_Request;
	false -> reply:   SOCKS_Reply;
};

type SOCKS_Request = record {
	version:  uint8;
	command:  uint8;
	port:     uint16;
	addr:     uint32;
	user:     uint8[] &until($element == 0);
	
	host:     case v4a of {
		true  -> name:  uint8[] &until($element == 0); # v4a
		false -> empty: uint8[] &length=0;
	} &requires(v4a);
	
	# FIXME: Can this be non-zero? If so we need to keep it for the
	# next analyzer.
	rest: bytestring &restofdata;
} &byteorder = bigendian &let {
	v4a: bool = (addr <= 0x000000ff);
};

type SOCKS_Reply = record {
	zero:    uint8;
	status:  uint8;
	port:     uint16;
	addr:     uint32;
	
	# FIXME: Can this be non-zero? If so we need to keep it for the
	# next analyzer.
	rest: bytestring &restofdata;
} &byteorder = bigendian;