
type GTPv1_Header = record {
	flags:     uint8;
	msg_type:  uint8;
	length:    uint16;
	teid:      uint32;
	opt:       case has_opt of {
		true  -> opt_hdr: GTPv1_Opt_Header;
		false -> no_opt:  empty;
	} &requires(has_opt);
	packet:    bytestring &restofdata;

} &let {
	version:  uint8 = (flags & 0xE0) >> 5;
	pt_flag:  bool  = flags & 0x10;
	rsv:      bool  = flags & 0x08;
	e_flag:   bool  = flags & 0x04;
	s_flag:   bool  = flags & 0x02;
	pn_flag:  bool  = flags & 0x01;
	has_opt:  bool  = flags & 0x07;
} &byteorder = littleendian;

type GTPv1_Opt_Header = record {
	seq:       uint16;
	n_pdu:     uint8;
	next_type: uint8;
}
