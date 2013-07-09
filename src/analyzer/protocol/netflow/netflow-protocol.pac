# Code written by Bernhard Ager (2007).

type NetFlowPacket = record {
	# Count and version are the first two fields, at least for
	# versions 1, 5, 7, 8 and 9.
	version: uint16;

	# This does not generate any code in current binpac.
	count: uint16 &check(count <= 30);

	header: NFHeader(version, count);
	records: NFRecord(version)[count];
} &byteorder = bigendian;

type NFHeader(version: uint16, count: uint16) = case version of {
	5 -> v5header: NFv5HeaderRest(count);
	9 -> v9header: NFv9HeaderRest(count);
	# default -> string: bytestring &restofdata &transient;
};

type NFv5HeaderRest(count: uint16) = record {
	sysuptime: uint32;
	unix_secs: uint32;
	unix_nsecs: uint32;
	flow_seq: uint32;
	eng_type: uint8;
	eng_id: uint8;
	sample_int: uint16;
} &let {
	delivered: bool =
		$context.flow.deliver_v5_header(count, sysuptime,
					     unix_secs, unix_nsecs,
					     flow_seq, eng_type,
					     eng_id, sample_int);
};

type NFv9HeaderRest(count: uint16) = record {
	sysuptime: uint32;
	unix_secs: uint32;
	pack_seq: uint32;
	src_id: uint32;
};

# We only handle version 5 and 9.  Others will throw a parsing exception.
type NFRecord(nf_version: uint32) = case nf_version of {
	5 -> v5: NFv5Record;
	9 -> v9: NFv9Record;
};

type NFv5Record = record {
	srcaddr: uint32;
	dstaddr: uint32;
	nexthop: uint32;
	input: uint16;
	output: uint16;
	dPkts: uint32;
	dOctets: uint32;
	first: uint32;
	last: uint32;
	srcport: uint16;
	dstport: uint16;
	: uint8;      # PAD1
	tcp_flags: uint8;
	prot: uint8;
	tos: uint8;
	src_as: uint16;
	dst_as: uint16;
	src_mask: uint8;
	dst_mask: uint8;
	: uint16;     # PAD2
} &let {
	delivered: bool =
		$context.flow.deliver_v5_record(srcaddr, dstaddr,
					      nexthop, input, output,
					      dPkts, dOctets, first,
					      last, srcport, dstport,
					      tcp_flags, prot, tos,
					      src_as, dst_as,
					      src_mask, dst_mask);
};

# Works for both template and data flow sets.  Data parsing will have
# to be done externally - no event generation yet.  We need sample
# flow data to implement that.
type NFv9Record = record {
	flowset_id: uint32;
	length: uint32;
	data: bytestring &length = length - 8;
};
