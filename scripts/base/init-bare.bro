@load base/bif/const.bif.bro
@load base/bif/types.bif

# Type declarations

## An ordered array of strings. The entries are indexed by successive numbers.
## Note that it depends on the usage whether the first index is zero or one.
##
## .. todo:: We need this type definition only for declaring builtin functions
##    via ``bifcl``. We should extend ``bifcl`` to understand composite types
##    directly and then remove this alias.
type string_array: table[count] of string;

## A set of strings.
##
## .. todo:: We need this type definition only for declaring builtin functions
##    via ``bifcl``. We should extend ``bifcl`` to understand composite types
##    directly and then remove this alias.
type string_set: set[string];

## A set of addresses.
##
## .. todo:: We need this type definition only for declaring builtin functions
##    via ``bifcl``. We should extend ``bifcl`` to understand composite types
##    directly and then remove this alias.
type addr_set: set[addr];

## A set of counts.
##
## .. todo:: We need this type definition only for declaring builtin functions
##    via ``bifcl``. We should extend ``bifcl`` to understand composite types
##    directly and then remove this alias.
type count_set: set[count];

## A vector of counts, used by some builtin functions to store a list of indices.
##
## .. todo:: We need this type definition only for declaring builtin functions
##    via ``bifcl``. We should extend ``bifcl`` to understand composite types
##    directly and then remove this alias.
type index_vec: vector of count;

## A vector of any, used by some builtin functions to store a list of varying
## types.
##
## .. todo:: We need this type definition only for declaring builtin functions
##    via ``bifcl``. We should extend ``bifcl`` to understand composite types
##    directly and then remove this alias.
type any_vec: vector of any;

## A vector of strings.
##
## .. todo:: We need this type definition only for declaring builtin functions
##    via ``bifcl``. We should extend ``bifcl`` to understand composite types
##    directly and then remove this alias.
type string_vec: vector of string;

## A vector of x509 opaques.
##
## .. todo:: We need this type definition only for declaring builtin functions
##    via ``bifcl``. We should extend ``bifcl`` to understand composite types
##    directly and then remove this alias.
type x509_opaque_vector: vector of opaque of x509;

## A vector of addresses.
##
## .. todo:: We need this type definition only for declaring builtin functions
##    via ``bifcl``. We should extend ``bifcl`` to understand composite types
##    directly and then remove this alias.
type addr_vec: vector of addr;

## A table of strings indexed by strings.
##
## .. todo:: We need this type definition only for declaring builtin functions
##    via ``bifcl``. We should extend ``bifcl`` to understand composite types
##    directly and then remove this alias.
type table_string_of_string: table[string] of string;

## A structure indicating a MIME type and strength of a match against
## file magic signatures.
##
## :bro:see:`file_magic`
type mime_match: record {
	strength: int;    ##< How strongly the signature matched.  Used for
	                  ##< prioritization when multiple file magic signatures
	                  ##< match.
	mime:     string; ##< The MIME type of the file magic signature match.
};

## A vector of file magic signature matches, ordered by strength of
## the signature, strongest first.
##
## :bro:see:`file_magic`
type mime_matches: vector of mime_match;

## A connection's transport-layer protocol. Note that Bro uses the term
## "connection" broadly, using flow semantics for ICMP and UDP.
type transport_proto: enum {
    unknown_transport,	##< An unknown transport-layer protocol.
    tcp,	##< TCP.
    udp,	##< UDP.
    icmp	##< ICMP.
};

## A connection's identifying 4-tuple of endpoints and ports.
##
## .. note:: It's actually a 5-tuple: the transport-layer protocol is stored as
##    part of the port values, `orig_p` and `resp_p`, and can be extracted from
##    them with :bro:id:`get_port_transport_proto`.
type conn_id: record {
	orig_h: addr;	##< The originator's IP address.
	orig_p: port;	##< The originator's port number.
	resp_h: addr;	##< The responder's IP address.
	resp_p: port;	##< The responder's port number.
} &log;

## Specifics about an ICMP conversation. ICMP events typically pass this in
## addition to :bro:type:`conn_id`.
##
## .. bro:see:: icmp_echo_reply icmp_echo_request icmp_redirect icmp_sent
##    icmp_time_exceeded icmp_unreachable
type icmp_conn: record {
	orig_h: addr;	##< The originator's IP address.
	resp_h: addr;	##< The responder's IP address.
	itype: count;	##< The ICMP type of the packet that triggered the instantiation of the record.
	icode: count;	##< The ICMP code of the packet that triggered the instantiation of the record.
	len: count;	##< The length of the ICMP payload of the packet that triggered the instantiation of the record.
	hlim: count;	##< The encapsulating IP header's Hop Limit value.
	v6: bool;	##< True if it's an ICMPv6 packet.
};

## Packet context part of an ICMP message. The fields of this record reflect the
## packet that is described by the context.
##
## .. bro:see:: icmp_time_exceeded icmp_unreachable
type icmp_context: record {
	id: conn_id;	##< The packet's 4-tuple.
	len: count;	##< The length of the IP packet (headers + payload).
	proto: count;	##< The packet's transport-layer protocol.
	frag_offset: count;	##< The packet's fragmentation offset.
	## True if the packet's IP header is not fully included in the context
	## or if there is not enough of the transport header to determine source
	## and destination ports. If that is the case, the appropriate fields
	## of this record will be set to null values.
	bad_hdr_len: bool;
	bad_checksum: bool;	##< True if the packet's IP checksum is not correct.
	MF: bool;	##< True if the packet's *more fragments* flag is set.
	DF: bool;	##< True if the packet's *don't fragment* flag is set.
};

## Values extracted from a Prefix Information option in an ICMPv6 neighbor
## discovery message as specified by :rfc:`4861`.
##
## .. bro:see:: icmp6_nd_option
type icmp6_nd_prefix_info: record {
	## Number of leading bits of the *prefix* that are valid.
	prefix_len: count;
	## Flag indicating the prefix can be used for on-link determination.
	L_flag: bool;
	## Autonomous address-configuration flag.
	A_flag: bool;
	## Length of time in seconds that the prefix is valid for purpose of
	## on-link determination (0xffffffff represents infinity).
	valid_lifetime: interval;
	## Length of time in seconds that the addresses generated from the
	## prefix via stateless address autoconfiguration remain preferred
	## (0xffffffff represents infinity).
	preferred_lifetime: interval;
	## An IP address or prefix of an IP address.  Use the *prefix_len* field
	## to convert this into a :bro:type:`subnet`.
	prefix: addr;
};

## Options extracted from ICMPv6 neighbor discovery messages as specified
## by :rfc:`4861`.
##
## .. bro:see:: icmp_router_solicitation icmp_router_advertisement
##    icmp_neighbor_advertisement icmp_neighbor_solicitation icmp_redirect
##    icmp6_nd_options
type icmp6_nd_option: record {
	## 8-bit identifier of the type of option.
	otype:        count;
	## 8-bit integer representing the length of the option (including the
	## type and length fields) in units of 8 octets.
	len:          count;
	## Source Link-Layer Address (Type 1) or Target Link-Layer Address (Type 2).
	## Byte ordering of this is dependent on the actual link-layer.
	link_address: string &optional;
	## Prefix Information (Type 3).
	prefix:       icmp6_nd_prefix_info &optional;
	## Redirected header (Type 4).  This field contains the context of the
	## original, redirected packet.
	redirect:     icmp_context &optional;
	## Recommended MTU for the link (Type 5).
	mtu:          count &optional;
	## The raw data of the option (everything after type & length fields),
	## useful for unknown option types or when the full option payload is
	## truncated in the captured packet.  In those cases, option fields
	## won't be pre-extracted into the fields above.
	payload:      string &optional;
};

## A type alias for a vector of ICMPv6 neighbor discovery message options.
type icmp6_nd_options: vector of icmp6_nd_option;

# A DNS mapping between IP address and hostname resolved by Bro's internal
# resolver.
#
# .. bro:see:: dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
#    dns_mapping_unverified dns_mapping_valid
type dns_mapping: record {
	## The time when the mapping was created, which corresponds to when
	## the DNS query was sent out.
	creation_time: time;
	## If the mapping is the result of a name lookup, the queried host name;
	## otherwise empty.
	req_host: string;
	## If the mapping is the result of a pointer lookup, the queried
	## address; otherwise null.
	req_addr: addr;
	## True if the lookup returned success. Only then are the result fields
	## valid.
	valid: bool;
	## If the mapping is the result of a pointer lookup, the resolved
	## hostname; otherwise empty.
	hostname: string;
	## If the mapping is the result of an address lookup, the resolved
	## address(es); otherwise empty.
	addrs: addr_set;
};

## A parsed host/port combination describing server endpoint for an upcoming
## data transfer.
##
## .. bro:see:: fmt_ftp_port parse_eftp_port parse_ftp_epsv parse_ftp_pasv
##    parse_ftp_port
type ftp_port: record {
	h: addr;	##< The host's address.
	p: port;	##< The host's port.
	valid: bool;	##< True if format was right. Only then are *h* and *p* valid.
};

## Statistics about what a TCP endpoint sent.
##
## .. bro:see:: conn_stats
type endpoint_stats: record {
	num_pkts: count;	##< Number of packets.
	num_rxmit: count;	##< Number of retransmissions.
	num_rxmit_bytes: count;	##< Number of retransmitted bytes.
	num_in_order: count;	##< Number of in-order packets.
	num_OO: count;	##< Number of out-of-order packets.
	num_repl: count;	##< Number of replicated packets (last packet was sent again).
	## Endian type used by the endpoint, if it could be determined from
	## the sequence numbers used. This is one of :bro:see:`ENDIAN_UNKNOWN`,
	## :bro:see:`ENDIAN_BIG`, :bro:see:`ENDIAN_LITTLE`, and
	## :bro:see:`ENDIAN_CONFUSED`.
	endian_type: count;
};

module Tunnel;
export {
	## Records the identity of an encapsulating parent of a tunneled connection.
	type EncapsulatingConn: record {
		## The 4-tuple of the encapsulating "connection". In case of an
		## IP-in-IP tunnel the ports will be set to 0. The direction
		## (i.e., orig and resp) are set according to the first tunneled
		## packet seen and not according to the side that established
		## the tunnel.
		cid: conn_id;
		## The type of tunnel.
		tunnel_type: Tunnel::Type;
		## A globally unique identifier that, for non-IP-in-IP tunnels,
		## cross-references the *uid* field of :bro:type:`connection`.
		uid: string &optional;
	} &log;
} # end export
module GLOBAL;

## A type alias for a vector of encapsulating "connections", i.e. for when
## there are tunnels within tunnels.
##
## .. todo:: We need this type definition only for declaring builtin functions
##    via ``bifcl``. We should extend ``bifcl`` to understand composite types
##    directly and then remove this alias.
type EncapsulatingConnVector: vector of Tunnel::EncapsulatingConn;

## Statistics about a :bro:type:`connection` endpoint.
##
## .. bro:see:: connection
type endpoint: record {
	size: count;	##< Logical size of data sent (for TCP: derived from sequence numbers).
	## Endpoint state. For a TCP connection, one of the constants:
	## :bro:see:`TCP_INACTIVE` :bro:see:`TCP_SYN_SENT`
	## :bro:see:`TCP_SYN_ACK_SENT` :bro:see:`TCP_PARTIAL`
	## :bro:see:`TCP_ESTABLISHED` :bro:see:`TCP_CLOSED` :bro:see:`TCP_RESET`.
	## For UDP, one of :bro:see:`UDP_ACTIVE` and :bro:see:`UDP_INACTIVE`.
	state: count;
	## Number of packets sent. Only set if :bro:id:`use_conn_size_analyzer`
	## is true.
	num_pkts: count &optional;
	## Number of IP-level bytes sent. Only set if
	## :bro:id:`use_conn_size_analyzer` is true.
	num_bytes_ip: count &optional;
	## The current IPv6 flow label that the connection endpoint is using.
	## Always 0 if the connection is over IPv4.
	flow_label: count;
};

## A connection. This is Bro's basic connection type describing IP- and
## transport-layer information about the conversation. Note that Bro uses a
## liberal interpretation of "connection" and associates instances of this type
## also with UDP and ICMP flows.
type connection: record {
	id: conn_id;	##< The connection's identifying 4-tuple.
	orig: endpoint;	##< Statistics about originator side.
	resp: endpoint;	##< Statistics about responder side.
	start_time: time;	##< The timestamp of the connection's first packet.
	## The duration of the conversation. Roughly speaking, this is the
	## interval between first and last data packet (low-level TCP details
	## may adjust it somewhat in ambiguous cases).
	duration: interval;
	## The set of services the connection is using as determined by Bro's
	## dynamic protocol detection. Each entry is the label of an analyzer
	## that confirmed that it could parse the connection payload.  While
	## typically, there will be at most one entry for each connection, in
	## principle it is possible that more than one protocol analyzer is able
	## to parse the same data. If so, all will be recorded. Also note that
	## the recorded services are independent of any transport-level protocols.
	service: set[string];
	addl: string;	##< Deprecated.
	hot: count;	##< Deprecated.
	history: string;	##< State history of connections. See *history* in :bro:see:`Conn::Info`.
	## A globally unique connection identifier. For each connection, Bro
	## creates an ID that is very likely unique across independent Bro runs.
	## These IDs can thus be used to tag and locate information associated
	## with that connection.
	uid: string;
	## If the connection is tunneled, this field contains information about
	## the encapsulating "connection(s)" with the outermost one starting
	## at index zero.  It's also always the first such encapsulation seen
	## for the connection unless the :bro:id:`tunnel_changed` event is
	## handled and reassigns this field to the new encapsulation.
	tunnel: EncapsulatingConnVector &optional;
};

## Default amount of time a file can be inactive before the file analysis
## gives up and discards any internal state related to the file.
const default_file_timeout_interval: interval = 2 mins &redef;

## Default amount of bytes that file analysis will buffer before raising
## :bro:see:`file_new`.
const default_file_bof_buffer_size: count = 1024 &redef;

## A file that Bro is analyzing.  This is Bro's type for describing the basic
## internal metadata collected about a "file", which is essentially just a
## byte stream that is e.g. pulled from a network connection or possibly
## some other input source.
type fa_file: record {
	## An identifier associated with a single file.
	id: string;

	## Identifier associated with a container file from which this one was
	## extracted as part of the file analysis.
	parent_id: string &optional;

	## An identification of the source of the file data.  E.g. it may be
	## a network protocol over which it was transferred, or a local file
	## path which was read, or some other input source.
	source: string;

	## If the source of this file is a network connection, this field
	## may be set to indicate the directionality.
	is_orig: bool &optional;

	## The set of connections over which the file was transferred.
	conns: table[conn_id] of connection &optional;

	## The time at which the last activity for the file was seen.
	last_active: time;

	## Number of bytes provided to the file analysis engine for the file.
	seen_bytes: count &default=0;

	## Total number of bytes that are supposed to comprise the full file.
	total_bytes: count &optional;

	## The number of bytes in the file stream that were completely missed
	## during the process of analysis e.g. due to dropped packets.
	missing_bytes: count &default=0;

	## The number of not all-in-sequence bytes in the file stream that
	## were delivered to file analyzers due to reassembly buffer overflow.
	overflow_bytes: count &default=0;

	## The amount of time between receiving new data for this file that
	## the analysis engine will wait before giving up on it.
	timeout_interval: interval &default=default_file_timeout_interval;

	## The number of bytes at the beginning of a file to save for later
	## inspection in the *bof_buffer* field.
	bof_buffer_size: count &default=default_file_bof_buffer_size;

	## The content of the beginning of a file up to *bof_buffer_size* bytes.
	## This is also the buffer that's used for file/mime type detection.
	bof_buffer: string &optional;

	## The mime type of the strongest file magic signature matches against
	## the data chunk in *bof_buffer*, or in the cases where no buffering
	## of the beginning of file occurs, an initial guess of the mime type
	## based on the first data seen.
	mime_type: string &optional;

	## All mime types that matched file magic signatures against the data
	## chunk in *bof_buffer*, in order of their strength value.
	mime_types: mime_matches &optional;
} &redef;

## Fields of a SYN packet.
##
## .. bro:see:: connection_SYN_packet
type SYN_packet: record {
	is_orig: bool;	##< True if the packet was sent the connection's originator.
	DF: bool;	##< True if the *don't fragment* is set in the IP header.
	ttl: count;	##< The IP header's time-to-live.
	size: count;	##< The size of the packet's payload as specified in the IP header.
	win_size: count;	##< The window size from the TCP header.
	win_scale: int;	##< The window scale option if present, or -1 if not.
	MSS: count;	##< The maximum segment size if present, or 0 if not.
	SACK_OK: bool;	##< True if the *SACK* option is present.
};

## Packet capture statistics.  All counts are cumulative.
##
## .. bro:see:: net_stats
type NetStats: record {
	pkts_recvd:   count &default=0;	##< Packets received by Bro.
	pkts_dropped: count &default=0;	##< Packets reported dropped by the system.
	## Packets seen on the link. Note that this may differ
	## from *pkts_recvd* because of a potential capture_filter. See
	## :doc:`/scripts/base/frameworks/packet-filter/main.bro`. Depending on the
	## packet capture system, this value may not be available and will then
	## be always set to zero.
	pkts_link:    count &default=0;
};

## Statistics about Bro's resource consumption.
##
## .. bro:see:: resource_usage
##
## .. note:: All process-level values refer to Bro's main process only, not to
##    the child process it spawns for doing communication.
type bro_resources: record {
	version: string;	##< Bro version string.
	debug: bool;	##< True if compiled with --enable-debug.
	start_time: time;	##< Start time of process.
	real_time: interval;	##< Elapsed real time since Bro started running.
	user_time: interval;	##< User CPU seconds.
	system_time: interval;	##< System CPU seconds.
	mem: count;		##< Maximum memory consumed, in KB.
	minor_faults: count;	##< Page faults not requiring actual I/O.
	major_faults: count;	##< Page faults requiring actual I/O.
	num_swap: count;	##< Times swapped out.
	blocking_input: count;	##< Blocking input operations.
	blocking_output: count;	##< Blocking output operations.
	num_context: count;	##< Number of involuntary context switches.

	num_TCP_conns: count;	##< Current number of TCP connections in memory.
	num_UDP_conns: count;	##< Current number of UDP flows in memory.
	num_ICMP_conns: count;	##< Current number of ICMP flows in memory.
	num_fragments: count;	##< Current number of fragments pending reassembly.
	num_packets: count;	##< Total number of packets processed to date.
	num_timers: count;	##< Current number of pending timers.
	num_events_queued: count;	##< Total number of events queued so far.
	num_events_dispatched: count;	##< Total number of events dispatched so far.

	max_TCP_conns: count;	##< Maximum number of concurrent TCP connections so far.
	max_UDP_conns: count;	##< Maximum number of concurrent UDP connections so far.
	max_ICMP_conns: count;	##< Maximum number of concurrent ICMP connections so far.
	max_fragments: count;	##< Maximum number of concurrently buffered fragments so far.
	max_timers: count;	##< Maximum number of concurrent timers pending so far.
};

## Summary statistics of all regular expression matchers.
##
## .. bro:see:: get_matcher_stats
type matcher_stats: record {
	matchers: count;	##< Number of distinct RE matchers.
	dfa_states: count;	##< Number of DFA states across all matchers.
	computed: count;	##< Number of computed DFA state transitions.
	mem: count;		##< Number of bytes used by DFA states.
	hits: count;		##< Number of cache hits.
	misses: count;		##< Number of cache misses.
	avg_nfa_states: count;	##< Average number of NFA states across all matchers.
};

## Statistics about number of gaps in TCP connections.
##
## .. bro:see:: gap_report get_gap_summary
type gap_info: record {
	ack_events: count;	##< How many ack events *could* have had gaps.
	ack_bytes: count;	##< How many bytes those covered.
	gap_events: count;	##< How many *did* have gaps.
	gap_bytes: count;	##< How many bytes were missing in the gaps.
};

## Deprecated.
##
## .. todo:: Remove. It's still declared internally but doesn't seem  used anywhere
##    else.
type packet: record {
	conn: connection;
	is_orig: bool;
	seq: count;	##< seq=k => it is the kth *packet* of the connection
	timestamp: time;
};

## Table type used to map variable names to their memory allocation.
##
## .. bro:see:: global_sizes
##
## .. todo:: We need this type definition only for declaring builtin functions
##    via ``bifcl``. We should extend ``bifcl`` to understand composite types
##    directly and then remove this alias.
type var_sizes: table[string] of count;

## Meta-information about a script-level identifier.
##
## .. bro:see:: global_ids id_table
type script_id: record {
	type_name: string;	##< The name of the identifier's type.
	exported: bool;	##< True if the identifier is exported.
	constant: bool;	##< True if the identifier is a constant.
	enum_constant: bool;	##< True if the identifier is an enum value.
	redefinable: bool;	##< True if the identifier is declared with the :bro:attr:`&redef` attribute.
	value: any &optional;	##< The current value of the identifier.
};

## Table type used to map script-level identifiers to meta-information
## describing them.
##
## .. bro:see:: global_ids script_id
##
## .. todo:: We need this type definition only for declaring builtin functions
##    via ``bifcl``. We should extend ``bifcl`` to understand composite types
##    directly and then remove this alias.
type id_table: table[string] of script_id;

## Meta-information about a record field.
##
## .. bro:see:: record_fields record_field_table
type record_field: record {
	type_name: string;	##< The name of the field's type.
	log: bool;	##< True if the field is declared with :bro:attr:`&log` attribute.
	## The current value of the field in the record instance passed into
	## :bro:see:`record_fields` (if it has one).
	value: any &optional;
	default_val: any &optional;	##< The value of the :bro:attr:`&default` attribute if defined.
};

## Table type used to map record field declarations to meta-information
## describing them.
##
## .. bro:see:: record_fields record_field
##
## .. todo:: We need this type definition only for declaring builtin functions
##    via ``bifcl``. We should extend ``bifcl`` to understand composite types
##    directly and then remove this alias.
type record_field_table: table[string] of record_field;

## Meta-information about a parameter to a function/event.
##
## .. bro:see:: call_argument_vector new_event
type call_argument: record {
	name: string;	##< The name of the parameter.
	type_name: string;	##< The name of the parameters's type.
	default_val: any &optional;	##< The value of the :bro:attr:`&default` attribute if defined.

	## The value of the parameter as passed into a given call instance.
	## Might be unset in the case a :bro:attr:`&default` attribute is
	## defined.
	value: any &optional;
};

## Vector type used to capture parameters of a function/event call.
##
## .. bro:see:: call_argument new_event
type call_argument_vector: vector of call_argument;

# todo:: Do we still need these here? Can they move into the packet filter
# framework?
#
# The following two variables are defined here until the core is not
# dependent on the names remaining as they are now.

## Set of BPF capture filters to use for capturing, indexed by a user-definable
## ID (which must be unique). If Bro is *not* configured with
## :bro:id:`PacketFilter::enable_auto_protocol_capture_filters`,
## all packets matching at least one of the filters in this table (and all in
## :bro:id:`restrict_filters`) will be analyzed.
##
## .. bro:see:: PacketFilter PacketFilter::enable_auto_protocol_capture_filters
##    PacketFilter::unrestricted_filter restrict_filters
global capture_filters: table[string] of string &redef;

## Set of BPF filters to restrict capturing, indexed by a user-definable ID
## (which must be unique).
##
## .. bro:see:: PacketFilter PacketFilter::enable_auto_protocol_capture_filters
##    PacketFilter::unrestricted_filter capture_filters
global restrict_filters: table[string] of string &redef;

## Enum type identifying dynamic BPF filters. These are used by
## :bro:see:`precompile_pcap_filter` and :bro:see:`precompile_pcap_filter`.
type PcapFilterID: enum { None };

## Deprecated.
##
## .. bro:see:: anonymize_addr
type IPAddrAnonymization: enum {
	KEEP_ORIG_ADDR,
	SEQUENTIALLY_NUMBERED,
	RANDOM_MD5,
	PREFIX_PRESERVING_A50,
	PREFIX_PRESERVING_MD5,
};

## Deprecated.
##
## .. bro:see:: anonymize_addr
type IPAddrAnonymizationClass: enum {
	ORIG_ADDR,
	RESP_ADDR,
	OTHER_ADDR,
};

## A locally unique ID identifying a communication peer. The ID is returned by
## :bro:id:`connect`.
##
## .. bro:see:: connect Communication
type peer_id: count;

## A communication peer.
##
## .. bro:see:: complete_handshake disconnect finished_send_state
##    get_event_peer get_local_event_peer remote_capture_filter
##    remote_connection_closed remote_connection_error
##    remote_connection_established remote_connection_handshake_done
##    remote_event_registered remote_log_peer remote_pong
##    request_remote_events request_remote_logs request_remote_sync
##    send_capture_filter send_current_packet send_id send_ping send_state
##    set_accept_state set_compression_level
##
## .. todo::The type's name is too narrow these days, should rename.
type event_peer: record {
	id: peer_id;	##< Locally unique ID of peer (returned by :bro:id:`connect`).
	host: addr;	##< The IP address of the peer.
	## Either the port we connected to at the peer; or our port the peer
	## connected to if the session is remotely initiated.
	p: port;
	is_local: bool;		##< True if this record describes the local process.
	descr: string;		##< The peer's :bro:see:`peer_description`.
	class: string &optional;	##< The self-assigned *class* of the peer. See :bro:see:`Communication::Node`.
};

## Deprecated.
##
## .. bro:see:: rotate_file rotate_file_by_name rotate_interval
type rotate_info: record {
	old_name: string;	##< Original filename.
	new_name: string;	##< File name after rotation.
	open: time;	##< Time when opened.
	close: time;	##< Time when closed.
};

### The following aren't presently used, though they should be.
# # Structures needed for subsequence computations (str_smith_waterman):
# #
# type sw_variant: enum {
#	SW_SINGLE,
#	SW_MULTIPLE,
# };

## Parameters for the Smith-Waterman algorithm.
##
## .. bro:see:: str_smith_waterman
type sw_params: record {
	## Minimum size of a substring, minimum "granularity".
	min_strlen: count &default = 3;

	## Smith-Waterman flavor to use.
	sw_variant: count &default = 0;
};

## Helper type for return value of Smith-Waterman algorithm.
##
## .. bro:see:: str_smith_waterman sw_substring_vec sw_substring sw_align_vec sw_params
type sw_align: record {
	str: string;	##< String a substring is part of.
	index: count;	##< Offset substring is located.
};

## Helper type for return value of Smith-Waterman algorithm.
##
## .. bro:see:: str_smith_waterman sw_substring_vec sw_substring sw_align sw_params
type sw_align_vec: vector of sw_align;

## Helper type for return value of Smith-Waterman algorithm.
##
## .. bro:see:: str_smith_waterman sw_substring_vec sw_align_vec sw_align sw_params
##
type sw_substring: record {
	str: string;	##< A substring.
	aligns: sw_align_vec;	##< All strings of which it's a substring.
	new: bool;	##< True if start of new alignment.
};

## Return type for Smith-Waterman algorithm.
##
## .. bro:see:: str_smith_waterman sw_substring sw_align_vec sw_align sw_params
##
## .. todo:: We need this type definition only for declaring builtin functions
##    via ``bifcl``. We should extend ``bifcl`` to understand composite types
##    directly and then remove this alias.
type sw_substring_vec: vector of sw_substring;

## Policy-level representation of a packet passed on by libpcap. The data
## includes the complete packet as returned by libpcap, including the link-layer
## header.
##
## .. bro:see:: dump_packet get_current_packet
type pcap_packet: record {
	ts_sec: count;	##< The non-fractional part of the packet's timestamp (i.e., full seconds since the epoch).
	ts_usec: count;	##< The fractional part of the packet's timestamp.
	caplen: count;	##< The number of bytes captured (<= *len*).
	len: count;	##< The length of the packet in bytes, including link-level header.
	data: string;	##< The payload of the packet, including link-level header.
};

## GeoIP location information.
##
## .. bro:see:: lookup_location
type geo_location: record {
	country_code: string &optional;	##< The country code.
	region: string &optional;	##< The region.
	city: string &optional;	##< The city.
	latitude: double &optional;	##< Latitude.
	longitude: double &optional;	##< Longitude.
} &log;

## Computed entropy values. The record captures a number of measures that are
## computed in parallel. See `A Pseudorandom Number Sequence Test Program
## <http://www.fourmilab.ch/random>`_ for more information, Bro uses the same
## code.
##
## .. bro:see:: entropy_test_add entropy_test_finish entropy_test_init find_entropy
type entropy_test_result: record {
	entropy: double;	##< Information density.
	chi_square: double;	##< Chi-Square value.
	mean: double;	##< Arithmetic Mean.
	monte_carlo_pi: double;	##< Monte-carlo value for pi.
	serial_correlation: double;	##< Serial correlation coefficient.
};

# Prototypes of Bro built-in functions.
@load base/bif/strings.bif
@load base/bif/bro.bif
@load base/bif/reporter.bif

## Deprecated. This is superseded by the new logging framework.
global log_file_name: function(tag: string): string &redef;

## Deprecated. This is superseded by the new logging framework.
global open_log_file: function(tag: string): file &redef;

## Specifies a directory for Bro to store its persistent state. All globals can
## be declared persistent via the :bro:attr:`&persistent` attribute.
const state_dir = ".state" &redef;

## Length of the delays inserted when storing state incrementally. To avoid
## dropping packets when serializing larger volumes of persistent state to
## disk, Bro interleaves the operation with continued packet processing.
const state_write_delay = 0.01 secs &redef;

global done_with_network = F;
event net_done(t: time) { done_with_network = T; }

function log_file_name(tag: string): string
	{
	local suffix = getenv("BRO_LOG_SUFFIX") == "" ? "log" : getenv("BRO_LOG_SUFFIX");
	return fmt("%s.%s", tag, suffix);
	}

function open_log_file(tag: string): file
	{
	return open(log_file_name(tag));
	}

## Internal function.
function add_interface(iold: string, inew: string): string
	{
	if ( iold == "" )
		return inew;
	else
		return fmt("%s %s", iold, inew);
	}

## Network interfaces to listen on. Use ``redef interfaces += "eth0"`` to
## extend.
global interfaces = "" &add_func = add_interface;

## Internal function.
function add_signature_file(sold: string, snew: string): string
	{
	if ( sold == "" )
		return snew;
	else
		return cat(sold, " ", snew);
	}

## Signature files to read. Use ``redef signature_files  += "foo.sig"`` to
## extend. Signature files added this way will be searched relative to
## ``BROPATH``.  Using the ``@load-sigs`` directive instead is preferred
## since that can search paths relative to the current script.
global signature_files = "" &add_func = add_signature_file;

## ``p0f`` fingerprint file to use. Will be searched relative to ``BROPATH``.
const passive_fingerprint_file = "base/misc/p0f.fp" &redef;

# TCP values for :bro:see:`endpoint` *state* field.
# todo:: these should go into an enum to make them autodoc'able.
const TCP_INACTIVE = 0;	##< Endpoint is still inactive.
const TCP_SYN_SENT = 1;	##< Endpoint has sent SYN.
const TCP_SYN_ACK_SENT = 2;	##< Endpoint has sent SYN/ACK.
const TCP_PARTIAL = 3;	##< Endpoint has sent data but no initial SYN.
const TCP_ESTABLISHED = 4;	##< Endpoint has finished initial handshake regularly.
const TCP_CLOSED = 5;	##< Endpoint has closed connection.
const TCP_RESET = 6;	##< Endpoint has sent RST.

# UDP values for :bro:see:`endpoint` *state* field.
# todo:: these should go into an enum to make them autodoc'able.
const UDP_INACTIVE = 0;	##< Endpoint is still inactive.
const UDP_ACTIVE = 1;	##< Endpoint has sent something.

## If true, don't verify checksums.  Useful for running on altered trace
## files, and for saving a few cycles, but at the risk of analyzing invalid
## data. Note that the ``-C`` command-line option overrides the setting of this
## variable.
const ignore_checksums = F &redef;

## If true, instantiate connection state when a partial connection
## (one missing its initial establishment negotiation) is seen.
const partial_connection_ok = T &redef;

## If true, instantiate connection state when a SYN/ACK is seen but not the
## initial SYN (even if :bro:see:`partial_connection_ok` is false).
const tcp_SYN_ack_ok = T &redef;

## If true, pass any undelivered to the signature engine before flushing the state.
## If a connection state is removed, there may still be some data waiting in the
## reassembler.
const tcp_match_undelivered = T &redef;

## Check up on the result of an initial SYN after this much time.
const tcp_SYN_timeout = 5 secs &redef;

## After a connection has closed, wait this long for further activity
## before checking whether to time out its state.
const tcp_session_timer = 6 secs &redef;

## When checking a closed connection for further activity, consider it
## inactive if there hasn't been any for this long.  Complain if the
## connection is reused before this much time has elapsed.
const tcp_connection_linger = 5 secs &redef;

## Wait this long upon seeing an initial SYN before timing out the
## connection attempt.
const tcp_attempt_delay = 5 secs &redef;

## Upon seeing a normal connection close, flush state after this much time.
const tcp_close_delay = 5 secs &redef;

## Upon seeing a RST, flush state after this much time.
const tcp_reset_delay = 5 secs &redef;

## Generate a :bro:id:`connection_partial_close` event this much time after one
## half of a partial connection closes, assuming there has been no subsequent
## activity.
const tcp_partial_close_delay = 3 secs &redef;

## If a connection belongs to an application that we don't analyze,
## time it out after this interval.  If 0 secs, then don't time it out (but
## :bro:see:`tcp_inactivity_timeout`, :bro:see:`udp_inactivity_timeout`, and
## :bro:see:`icmp_inactivity_timeout` still apply).
const non_analyzed_lifetime = 0 secs &redef;

## If a TCP connection is inactive, time it out after this interval. If 0 secs,
## then don't time it out.
##
## .. bro:see:: udp_inactivity_timeout icmp_inactivity_timeout set_inactivity_timeout
const tcp_inactivity_timeout = 5 min &redef;

## If a UDP flow is inactive, time it out after this interval. If 0 secs, then
## don't time it out.
##
## .. bro:see:: tcp_inactivity_timeout icmp_inactivity_timeout set_inactivity_timeout
const udp_inactivity_timeout = 1 min &redef;

## If an ICMP flow is inactive, time it out after this interval. If 0 secs, then
## don't time it out.
##
## .. bro:see:: tcp_inactivity_timeout udp_inactivity_timeout set_inactivity_timeout
const icmp_inactivity_timeout = 1 min &redef;

## Number of FINs/RSTs in a row that constitute a "storm". Storms are reported
## as ``weird`` via the notice framework, and they must also come within
## intervals of at most :bro:see:`tcp_storm_interarrival_thresh`.
##
## .. bro:see:: tcp_storm_interarrival_thresh
const tcp_storm_thresh = 1000 &redef;

## FINs/RSTs must come with this much time or less between them to be
## considered a "storm".
##
## .. bro:see:: tcp_storm_thresh
const tcp_storm_interarrival_thresh = 1 sec &redef;

## Maximum amount of data that might plausibly be sent in an initial flight
## (prior to receiving any acks).  Used to determine whether we must not be
## seeing our peer's ACKs.  Set to zero to turn off this determination.
##
## .. bro:see:: tcp_max_above_hole_without_any_acks tcp_excessive_data_without_further_acks
const tcp_max_initial_window = 4096 &redef;

## If we're not seeing our peer's ACKs, the maximum volume of data above a
## sequence hole that we'll tolerate before assuming that there's been a packet
## drop and we should give up on tracking a connection. If set to zero, then we
## don't ever give up.
##
## .. bro:see:: tcp_max_initial_window tcp_excessive_data_without_further_acks
const tcp_max_above_hole_without_any_acks = 4096 &redef;

## If we've seen this much data without any of it being acked, we give up
## on that connection to avoid memory exhaustion due to buffering all that
## stuff.  If set to zero, then we don't ever give up.  Ideally, Bro would
## track the current window on a connection and use it to infer that data
## has in fact gone too far, but for now we just make this quite beefy.
##
## .. bro:see:: tcp_max_initial_window tcp_max_above_hole_without_any_acks
const tcp_excessive_data_without_further_acks = 10 * 1024 * 1024 &redef;

## For services without a handler, these sets define originator-side ports
## that still trigger reassembly.
##
## .. bro:see:: tcp_reassembler_ports_resp
const tcp_reassembler_ports_orig: set[port] = {} &redef;

## For services without a handler, these sets define responder-side ports
## that still trigger reassembly.
##
## .. bro:see:: tcp_reassembler_ports_orig
const tcp_reassembler_ports_resp: set[port] = {} &redef;

## Defines destination TCP ports for which the contents of the originator stream
## should be delivered via :bro:see:`tcp_contents`.
##
## .. bro:see:: tcp_content_delivery_ports_resp tcp_content_deliver_all_orig
##    tcp_content_deliver_all_resp udp_content_delivery_ports_orig
##    udp_content_delivery_ports_resp  udp_content_deliver_all_orig
##    udp_content_deliver_all_resp  tcp_contents
const tcp_content_delivery_ports_orig: table[port] of bool = {} &redef;

## Defines destination TCP ports for which the contents of the responder stream
## should be delivered via :bro:see:`tcp_contents`.
##
## .. bro:see:: tcp_content_delivery_ports_orig tcp_content_deliver_all_orig
##    tcp_content_deliver_all_resp udp_content_delivery_ports_orig
##    udp_content_delivery_ports_resp  udp_content_deliver_all_orig
##    udp_content_deliver_all_resp tcp_contents
const tcp_content_delivery_ports_resp: table[port] of bool = {} &redef;

## If true, all TCP originator-side traffic is reported via
## :bro:see:`tcp_contents`.
##
## .. bro:see:: tcp_content_delivery_ports_orig tcp_content_delivery_ports_resp
##    tcp_content_deliver_all_resp udp_content_delivery_ports_orig
##    udp_content_delivery_ports_resp  udp_content_deliver_all_orig
##    udp_content_deliver_all_resp tcp_contents
const tcp_content_deliver_all_orig = F &redef;

## If true, all TCP responder-side traffic is reported via
## :bro:see:`tcp_contents`.
##
## .. bro:see:: tcp_content_delivery_ports_orig
##    tcp_content_delivery_ports_resp
##    tcp_content_deliver_all_orig udp_content_delivery_ports_orig
##    udp_content_delivery_ports_resp  udp_content_deliver_all_orig
##    udp_content_deliver_all_resp tcp_contents
const tcp_content_deliver_all_resp = F &redef;

## Defines UDP destination ports for which the contents of the originator stream
## should be delivered via :bro:see:`udp_contents`.
##
## .. bro:see:: tcp_content_delivery_ports_orig
##    tcp_content_delivery_ports_resp
##    tcp_content_deliver_all_orig tcp_content_deliver_all_resp
##    udp_content_delivery_ports_resp  udp_content_deliver_all_orig
##    udp_content_deliver_all_resp  udp_contents
const udp_content_delivery_ports_orig: table[port] of bool = {} &redef;

## Defines UDP destination ports for which the contents of the responder stream
## should be delivered via :bro:see:`udp_contents`.
##
## .. bro:see:: tcp_content_delivery_ports_orig
##    tcp_content_delivery_ports_resp tcp_content_deliver_all_orig
##    tcp_content_deliver_all_resp udp_content_delivery_ports_orig
##    udp_content_deliver_all_orig udp_content_deliver_all_resp udp_contents
const udp_content_delivery_ports_resp: table[port] of bool = {} &redef;

## If true, all UDP originator-side traffic is reported via
## :bro:see:`udp_contents`.
##
## .. bro:see:: tcp_content_delivery_ports_orig
##    tcp_content_delivery_ports_resp tcp_content_deliver_all_resp
##    tcp_content_delivery_ports_orig udp_content_delivery_ports_orig
##    udp_content_delivery_ports_resp  udp_content_deliver_all_resp
##    udp_contents
const udp_content_deliver_all_orig = F &redef;

## If true, all UDP responder-side traffic is reported via
## :bro:see:`udp_contents`.
##
## .. bro:see:: tcp_content_delivery_ports_orig
##    tcp_content_delivery_ports_resp tcp_content_deliver_all_resp
##    tcp_content_delivery_ports_orig udp_content_delivery_ports_orig
##    udp_content_delivery_ports_resp  udp_content_deliver_all_orig
##    udp_contents
const udp_content_deliver_all_resp = F &redef;

## Check for expired table entries after this amount of time.
##
## .. bro:see:: table_incremental_step table_expire_delay
const table_expire_interval = 10 secs &redef;

## When expiring/serializing table entries, don't work on more than this many
## table entries at a time.
##
## .. bro:see:: table_expire_interval table_expire_delay
const table_incremental_step = 5000 &redef;

## When expiring table entries, wait this amount of time before checking the
## next chunk of entries.
##
## .. bro:see:: table_expire_interval table_incremental_step
const table_expire_delay = 0.01 secs &redef;

## Time to wait before timing out a DNS request.
const dns_session_timeout = 10 sec &redef;

## Time to wait before timing out an NTP request.
const ntp_session_timeout = 300 sec &redef;

## Time to wait before timing out an RPC request.
const rpc_timeout = 24 sec &redef;

## How long to hold onto fragments for possible reassembly.  A value of 0.0
## means "forever", which resists evasion, but can lead to state accrual.
const frag_timeout = 0.0 sec &redef;

## If positive, indicates the encapsulation header size that should
## be skipped. This applies to all packets.
const encap_hdr_size = 0 &redef;

## Whether to use the ``ConnSize`` analyzer to count the number of packets and
## IP-level bytes transferred by each endpoint. If true, these values are
## returned in the connection's :bro:see:`endpoint` record value.
const use_conn_size_analyzer = T &redef;

# todo:: these should go into an enum to make them autodoc'able.
const ENDIAN_UNKNOWN = 0;	##< Endian not yet determined.
const ENDIAN_LITTLE = 1;	##< Little endian.
const ENDIAN_BIG = 2;	##< Big endian.
const ENDIAN_CONFUSED = 3;	##< Tried to determine endian, but failed.

## Deprecated.
function append_addl(c: connection, addl: string)
	{
	if ( c$addl == "" )
		c$addl= addl;

	else if ( addl !in c$addl )
		c$addl = fmt("%s %s", c$addl, addl);
	}

## Deprecated.
function append_addl_marker(c: connection, addl: string, marker: string)
	{
	if ( c$addl == "" )
		c$addl= addl;

	else if ( addl !in c$addl )
		c$addl = fmt("%s%s%s", c$addl, marker, addl);
	}


# Values for :bro:see:`set_contents_file` *direction* argument.
# todo:: these should go into an enum to make them autodoc'able
const CONTENTS_NONE = 0;	##< Turn off recording of contents.
const CONTENTS_ORIG = 1;	##< Record originator contents.
const CONTENTS_RESP = 2;	##< Record responder contents.
const CONTENTS_BOTH = 3;	##< Record both originator and responder contents.

# Values for code of ICMP *unreachable* messages. The list is not exhaustive.
# todo:: these should go into an enum to make them autodoc'able
#
# .. bro:see:: :bro:see:`icmp_unreachable `
const ICMP_UNREACH_NET = 0;	##< Network unreachable.
const ICMP_UNREACH_HOST = 1;	##< Host unreachable.
const ICMP_UNREACH_PROTOCOL = 2;	##< Protocol unreachable.
const ICMP_UNREACH_PORT = 3;	##< Port unreachable.
const ICMP_UNREACH_NEEDFRAG = 4;	##< Fragment needed.
const ICMP_UNREACH_ADMIN_PROHIB = 13;	##< Administratively prohibited.

# Definitions for access to packet headers.  Currently only used for
# discarders.
# todo:: these should go into an enum to make them autodoc'able
const IPPROTO_IP = 0;			##< Dummy for IP.
const IPPROTO_ICMP = 1;			##< Control message protocol.
const IPPROTO_IGMP = 2;			##< Group management protocol.
const IPPROTO_IPIP = 4;			##< IP encapsulation in IP.
const IPPROTO_TCP = 6;			##< TCP.
const IPPROTO_UDP = 17;			##< User datagram protocol.
const IPPROTO_IPV6 = 41;		##< IPv6 header.
const IPPROTO_ICMPV6 = 58;		##< ICMP for IPv6.
const IPPROTO_RAW = 255;		##< Raw IP packet.

# Definitions for IPv6 extension headers.
const IPPROTO_HOPOPTS = 0;		##< IPv6 hop-by-hop-options header.
const IPPROTO_ROUTING = 43;		##< IPv6 routing header.
const IPPROTO_FRAGMENT = 44;		##< IPv6 fragment header.
const IPPROTO_ESP = 50;			##< IPv6 encapsulating security payload header.
const IPPROTO_AH = 51;			##< IPv6 authentication header.
const IPPROTO_NONE = 59;		##< IPv6 no next header.
const IPPROTO_DSTOPTS = 60;		##< IPv6 destination options header.
const IPPROTO_MOBILITY = 135;		##< IPv6 mobility header.

## Values extracted from an IPv6 extension header's (e.g. hop-by-hop or
## destination option headers) option field.
##
## .. bro:see:: ip6_hdr ip6_ext_hdr ip6_hopopts ip6_dstopts
type ip6_option: record {
	otype: count;	##< Option type.
	len: count;		##< Option data length.
	data: string;	##< Option data.
};

## A type alias for a vector of IPv6 options.
type ip6_options: vector of ip6_option;

## Values extracted from an IPv6 Hop-by-Hop options extension header.
##
## .. bro:see:: pkt_hdr ip4_hdr ip6_hdr ip6_ext_hdr ip6_option
type ip6_hopopts: record {
	## Protocol number of the next header (RFC 1700 et seq., IANA assigned
	## number), e.g. :bro:id:`IPPROTO_ICMP`.
	nxt: count;
	## Length of header in 8-octet units, excluding first unit.
	len: count;
	## The TLV encoded options;
	options: ip6_options;
};

## Values extracted from an IPv6 Destination options extension header.
##
## .. bro:see:: pkt_hdr ip4_hdr ip6_hdr ip6_ext_hdr ip6_option
type ip6_dstopts: record {
	## Protocol number of the next header (RFC 1700 et seq., IANA assigned
	## number), e.g. :bro:id:`IPPROTO_ICMP`.
	nxt: count;
	## Length of header in 8-octet units, excluding first unit.
	len: count;
	## The TLV encoded options;
	options: ip6_options;
};

## Values extracted from an IPv6 Routing extension header.
##
## .. bro:see:: pkt_hdr ip4_hdr ip6_hdr ip6_ext_hdr
type ip6_routing: record {
	## Protocol number of the next header (RFC 1700 et seq., IANA assigned
	## number), e.g. :bro:id:`IPPROTO_ICMP`.
	nxt: count;
	## Length of header in 8-octet units, excluding first unit.
	len: count;
	## Routing type.
	rtype: count;
	## Segments left.
	segleft: count;
	## Type-specific data.
	data: string;
};

## Values extracted from an IPv6 Fragment extension header.
##
## .. bro:see:: pkt_hdr ip4_hdr ip6_hdr ip6_ext_hdr
type ip6_fragment: record {
	## Protocol number of the next header (RFC 1700 et seq., IANA assigned
	## number), e.g. :bro:id:`IPPROTO_ICMP`.
	nxt: count;
	## 8-bit reserved field.
	rsv1: count;
	## Fragmentation offset.
	offset: count;
	## 2-bit reserved field.
	rsv2: count;
	## More fragments.
	more: bool;
	## Fragment identification.
	id: count;
};

## Values extracted from an IPv6 Authentication extension header.
##
## .. bro:see:: pkt_hdr ip4_hdr ip6_hdr ip6_ext_hdr
type ip6_ah: record {
	## Protocol number of the next header (RFC 1700 et seq., IANA assigned
	## number), e.g. :bro:id:`IPPROTO_ICMP`.
	nxt: count;
	## Length of header in 4-octet units, excluding first two units.
	len: count;
	## Reserved field.
	rsv: count;
	## Security Parameter Index.
	spi: count;
	## Sequence number, unset in the case that *len* field is zero.
	seq: count &optional;
	## Authentication data, unset in the case that *len* field is zero.
	data: string &optional;
};

## Values extracted from an IPv6 ESP extension header.
##
## .. bro:see:: pkt_hdr ip4_hdr ip6_hdr ip6_ext_hdr
type ip6_esp: record {
	## Security Parameters Index.
	spi: count;
	## Sequence number.
	seq: count;
};

## Values extracted from an IPv6 Mobility Binding Refresh Request message.
##
## .. bro:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr ip6_mobility_msg
type ip6_mobility_brr: record {
	## Reserved.
	rsv: count;
	## Mobility Options.
	options: vector of ip6_option;
};

## Values extracted from an IPv6 Mobility Home Test Init message.
##
## .. bro:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr ip6_mobility_msg
type ip6_mobility_hoti: record {
	## Reserved.
	rsv: count;
	## Home Init Cookie.
	cookie: count;
	## Mobility Options.
	options: vector of ip6_option;
};

## Values extracted from an IPv6 Mobility Care-of Test Init message.
##
## .. bro:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr ip6_mobility_msg
type ip6_mobility_coti: record {
	## Reserved.
	rsv: count;
	## Care-of Init Cookie.
	cookie: count;
	## Mobility Options.
	options: vector of ip6_option;
};

## Values extracted from an IPv6 Mobility Home Test message.
##
## .. bro:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr ip6_mobility_msg
type ip6_mobility_hot: record {
	## Home Nonce Index.
	nonce_idx: count;
	## Home Init Cookie.
	cookie: count;
	## Home Keygen Token.
	token: count;
	## Mobility Options.
	options: vector of ip6_option;
};

## Values extracted from an IPv6 Mobility Care-of Test message.
##
## .. bro:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr ip6_mobility_msg
type ip6_mobility_cot: record {
	## Care-of Nonce Index.
	nonce_idx: count;
	## Care-of Init Cookie.
	cookie: count;
	## Care-of Keygen Token.
	token: count;
	## Mobility Options.
	options: vector of ip6_option;
};

## Values extracted from an IPv6 Mobility Binding Update message.
##
## .. bro:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr ip6_mobility_msg
type ip6_mobility_bu: record {
	## Sequence number.
	seq: count;
	## Acknowledge bit.
	a: bool;
	## Home Registration bit.
	h: bool;
	## Link-Local Address Compatibility bit.
	l: bool;
	## Key Management Mobility Capability bit.
	k: bool;
	## Lifetime.
	life: count;
	## Mobility Options.
	options: vector of ip6_option;
};

## Values extracted from an IPv6 Mobility Binding Acknowledgement message.
##
## .. bro:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr ip6_mobility_msg
type ip6_mobility_back: record {
	## Status.
	status: count;
	## Key Management Mobility Capability.
	k: bool;
	## Sequence number.
	seq: count;
	## Lifetime.
	life: count;
	## Mobility Options.
	options: vector of ip6_option;
};

## Values extracted from an IPv6 Mobility Binding Error message.
##
## .. bro:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr ip6_mobility_msg
type ip6_mobility_be: record {
	## Status.
	status: count;
	## Home Address.
	hoa: addr;
	## Mobility Options.
	options: vector of ip6_option;
};

## Values extracted from an IPv6 Mobility header's message data.
##
## .. bro:see:: ip6_mobility_hdr ip6_hdr ip6_ext_hdr
type ip6_mobility_msg: record {
	## The type of message from the header's MH Type field.
	id: count;
	## Binding Refresh Request.
	brr: ip6_mobility_brr &optional;
	## Home Test Init.
	hoti: ip6_mobility_hoti &optional;
	## Care-of Test Init.
	coti: ip6_mobility_coti &optional;
	## Home Test.
	hot: ip6_mobility_hot &optional;
	## Care-of Test.
	cot: ip6_mobility_cot &optional;
	## Binding Update.
	bu: ip6_mobility_bu &optional;
	## Binding Acknowledgement.
	back: ip6_mobility_back &optional;
	## Binding Error.
	be: ip6_mobility_be &optional;
};

## Values extracted from an IPv6 Mobility header.
##
## .. bro:see:: pkt_hdr ip4_hdr ip6_hdr ip6_ext_hdr
type ip6_mobility_hdr: record {
	## Protocol number of the next header (RFC 1700 et seq., IANA assigned
	## number), e.g. :bro:id:`IPPROTO_ICMP`.
	nxt: count;
	## Length of header in 8-octet units, excluding first unit.
	len: count;
	## Mobility header type used to identify header's the message.
	mh_type: count;
	## Reserved field.
	rsv: count;
	## Mobility header checksum.
	chksum: count;
	## Mobility header message
	msg: ip6_mobility_msg;
};

## A general container for a more specific IPv6 extension header.
##
## .. bro:see:: pkt_hdr ip4_hdr ip6_hopopts ip6_dstopts ip6_routing ip6_fragment
##    ip6_ah ip6_esp
type ip6_ext_hdr: record {
	## The RFC 1700 et seq. IANA assigned number identifying the type of
	## the extension header.
	id: count;
	## Hop-by-hop option extension header.
	hopopts: ip6_hopopts &optional;
	## Destination option extension header.
	dstopts: ip6_dstopts &optional;
	## Routing extension header.
	routing: ip6_routing &optional;
	## Fragment header.
	fragment: ip6_fragment &optional;
	## Authentication extension header.
	ah: ip6_ah &optional;
	## Encapsulating security payload header.
	esp: ip6_esp &optional;
	## Mobility header.
	mobility: ip6_mobility_hdr &optional;
};

## A type alias for a vector of IPv6 extension headers.
type ip6_ext_hdr_chain: vector of ip6_ext_hdr;

## Values extracted from an IPv6 header.
##
## .. bro:see:: pkt_hdr ip4_hdr ip6_ext_hdr ip6_hopopts ip6_dstopts
##    ip6_routing ip6_fragment ip6_ah ip6_esp
type ip6_hdr: record {
	class: count;			##< Traffic class.
	flow: count;			##< Flow label.
	len: count;			##< Payload length.
	nxt: count;			##< Protocol number of the next header
					##< (RFC 1700 et seq., IANA assigned number)
					##< e.g. :bro:id:`IPPROTO_ICMP`.
	hlim: count;			##< Hop limit.
	src: addr;			##< Source address.
	dst: addr;			##< Destination address.
	exts: ip6_ext_hdr_chain;	##< Extension header chain.
};

## Values extracted from an IPv4 header.
##
## .. bro:see:: pkt_hdr ip6_hdr discarder_check_ip
type ip4_hdr: record {
	hl: count;		##< Header length in bytes.
	tos: count;		##< Type of service.
	len: count;		##< Total length.
	id: count;		##< Identification.
	ttl: count;		##< Time to live.
	p: count;		##< Protocol.
	src: addr;		##< Source address.
	dst: addr;		##< Destination address.
};

# TCP flags.
#
# todo:: these should go into an enum to make them autodoc'able
const TH_FIN = 1;	##< FIN.
const TH_SYN = 2;	##< SYN.
const TH_RST = 4;	##< RST.
const TH_PUSH = 8;	##< PUSH.
const TH_ACK = 16;	##< ACK.
const TH_URG = 32;	##< URG.
const TH_FLAGS = 63;	##< Mask combining all flags.

## Values extracted from a TCP header.
##
## .. bro:see:: pkt_hdr discarder_check_tcp
type tcp_hdr: record {
	sport: port;		##< source port.
	dport: port;		##< destination port
	seq: count;		##< sequence number
	ack: count;		##< acknowledgement number
	hl: count;		##< header length (in bytes)
	dl: count;		##< data length (xxx: not in original tcphdr!)
	flags: count;		##< flags
	win: count;		##< window
};

## Values extracted from a UDP header.
##
## .. bro:see:: pkt_hdr discarder_check_udp
type udp_hdr: record {
	sport: port;		##< source port
	dport: port;		##< destination port
	ulen: count;		##< udp length
};

## Values extracted from an ICMP header.
##
## .. bro:see:: pkt_hdr discarder_check_icmp
type icmp_hdr: record {
	icmp_type: count;	##< type of message
};

## A packet header, consisting of an IP header and transport-layer header.
##
## .. bro:see:: new_packet
type pkt_hdr: record {
	ip: ip4_hdr &optional;		##< The IPv4 header if an IPv4 packet.
	ip6: ip6_hdr &optional;		##< The IPv6 header if an IPv6 packet.
	tcp: tcp_hdr &optional;		##< The TCP header if a TCP packet.
	udp: udp_hdr &optional;		##< The UDP header if a UDP packet.
	icmp: icmp_hdr &optional;	##< The ICMP header if an ICMP packet.
};

## A Teredo origin indication header.  See :rfc:`4380` for more information
## about the Teredo protocol.
##
## .. bro:see:: teredo_bubble teredo_origin_indication teredo_authentication
##    teredo_hdr
type teredo_auth: record {
	id:      string;  ##< Teredo client identifier.
	value:   string;  ##< HMAC-SHA1 over shared secret key between client and
	                  ##< server, nonce, confirmation byte, origin indication
	                  ##< (if present), and the IPv6 packet.
	nonce:   count;   ##< Nonce chosen by Teredo client to be repeated by
	                  ##< Teredo server.
	confirm: count;   ##< Confirmation byte to be set to 0 by Teredo client
	                  ##< and non-zero by server if client needs new key.
};

## A Teredo authentication header.  See :rfc:`4380` for more information
## about the Teredo protocol.
##
## .. bro:see:: teredo_bubble teredo_origin_indication teredo_authentication
##    teredo_hdr
type teredo_origin: record {
	p: port; ##< Unobfuscated UDP port of Teredo client.
	a: addr; ##< Unobfuscated IPv4 address of Teredo client.
};

## A Teredo packet header.  See :rfc:`4380` for more information about the
## Teredo protocol.
##
## .. bro:see:: teredo_bubble teredo_origin_indication teredo_authentication
type teredo_hdr: record {
	auth:   teredo_auth &optional;   ##< Teredo authentication header.
	origin: teredo_origin &optional; ##< Teredo origin indication header.
	hdr:    pkt_hdr;                 ##< IPv6 and transport protocol headers.
};

## A GTPv1 (GPRS Tunneling Protocol) header.
type gtpv1_hdr: record {
	## The 3-bit version field, which for GTPv1 should be 1.
	version:   count;
	## Protocol Type value differentiates GTP (value 1) from GTP' (value 0).
	pt_flag:   bool;
	## Reserved field, should be 0.
	rsv:       bool;
	## Extension Header flag.  When 0, the *next_type* field may or may not
	## be present, but shouldn't be meaningful.  When 1, *next_type* is
	## present and meaningful.
	e_flag:    bool;
	## Sequence Number flag.  When 0, the *seq* field may or may not
	## be present, but shouldn't be meaningful.  When 1, *seq* is
	## present and meaningful.
	s_flag:    bool;
	## N-PDU flag.  When 0, the *n_pdu* field may or may not
	## be present, but shouldn't be meaningful.  When 1, *n_pdu* is
	## present and meaningful.
	pn_flag:   bool;
	## Message Type.  A value of 255 indicates user-plane data is encapsulated.
	msg_type:  count;
	## Length of the GTP packet payload (the rest of the packet following
	## the mandatory 8-byte GTP header).
	length:    count;
	## Tunnel Endpoint Identifier.  Unambiguously identifies a tunnel
	## endpoint in receiving GTP-U or GTP-C protocol entity.
	teid:      count;
	## Sequence Number.  Set if any *e_flag*, *s_flag*, or *pn_flag* field
	## is set.
	seq:       count &optional;
	## N-PDU Number.  Set if any *e_flag*, *s_flag*, or *pn_flag* field is set.
	n_pdu:     count &optional;
	## Next Extension Header Type.  Set if any *e_flag*, *s_flag*, or
	## *pn_flag* field is set.
	next_type: count &optional;
};

type gtp_cause: count;
type gtp_imsi: count;
type gtp_teardown_ind: bool;
type gtp_nsapi: count;
type gtp_recovery: count;
type gtp_teid1: count;
type gtp_teid_control_plane: count;
type gtp_charging_id: count;
type gtp_charging_gateway_addr: addr;
type gtp_trace_reference: count;
type gtp_trace_type: count;
type gtp_tft: string;
type gtp_trigger_id: string;
type gtp_omc_id: string;
type gtp_reordering_required: bool;
type gtp_proto_config_options: string;
type gtp_charging_characteristics: count;
type gtp_selection_mode: count;
type gtp_access_point_name: string;
type gtp_msisdn: string;

type gtp_gsn_addr: record {
	## If the GSN Address information element has length 4 or 16, then this
	## field is set to be the informational element's value interpreted as
	## an IPv4 or IPv6 address, respectively.
	ip: addr &optional;
	## This field is set if it's not an IPv4 or IPv6 address.
	other: string &optional;
};

type gtp_end_user_addr: record {
	pdp_type_org: count;
	pdp_type_num: count;
	## Set if the End User Address information element is IPv4/IPv6.
	pdp_ip: addr &optional;
	## Set if the End User Address information element isn't IPv4/IPv6.
	pdp_other_addr: string &optional;
};

type gtp_rai: record {
	mcc: count;
	mnc: count;
	lac: count;
	rac: count;
};

type gtp_qos_profile: record {
	priority: count;
	data: string;
};

type gtp_private_extension: record {
	id: count;
	value: string;
};

type gtp_create_pdp_ctx_request_elements: record {
	imsi:             gtp_imsi &optional;
	rai:              gtp_rai &optional;
	recovery:         gtp_recovery &optional;
	select_mode:      gtp_selection_mode &optional;
	data1:            gtp_teid1;
	cp:               gtp_teid_control_plane &optional;
	nsapi:            gtp_nsapi;
	linked_nsapi:     gtp_nsapi &optional;
	charge_character: gtp_charging_characteristics &optional;
	trace_ref:        gtp_trace_reference &optional;
	trace_type:       gtp_trace_type &optional;
	end_user_addr:    gtp_end_user_addr &optional;
	ap_name:          gtp_access_point_name &optional;
	opts:             gtp_proto_config_options &optional;
	signal_addr:      gtp_gsn_addr;
	user_addr:        gtp_gsn_addr;
	msisdn:           gtp_msisdn &optional;
	qos_prof:         gtp_qos_profile;
	tft:              gtp_tft &optional;
	trigger_id:       gtp_trigger_id &optional;
	omc_id:           gtp_omc_id &optional;
	ext:              gtp_private_extension &optional;
};

type gtp_create_pdp_ctx_response_elements: record {
	cause:          gtp_cause;
	reorder_req:    gtp_reordering_required &optional;
	recovery:       gtp_recovery &optional;
	data1:          gtp_teid1 &optional;
	cp:             gtp_teid_control_plane &optional;
	charging_id:    gtp_charging_id &optional;
	end_user_addr:  gtp_end_user_addr &optional;
	opts:           gtp_proto_config_options &optional;
	cp_addr:        gtp_gsn_addr &optional;
	user_addr:      gtp_gsn_addr &optional;
	qos_prof:       gtp_qos_profile &optional;
	charge_gateway: gtp_charging_gateway_addr &optional;
	ext:            gtp_private_extension &optional;
};

type gtp_update_pdp_ctx_request_elements: record {
	imsi:          gtp_imsi &optional;
	rai:           gtp_rai &optional;
	recovery:      gtp_recovery &optional;
	data1:         gtp_teid1;
	cp:            gtp_teid_control_plane &optional;
	nsapi:         gtp_nsapi;
	trace_ref:     gtp_trace_reference &optional;
	trace_type:    gtp_trace_type &optional;
	cp_addr:       gtp_gsn_addr;
	user_addr:     gtp_gsn_addr;
	qos_prof:      gtp_qos_profile;
	tft:           gtp_tft &optional;
	trigger_id:    gtp_trigger_id &optional;
	omc_id:        gtp_omc_id &optional;
	ext:           gtp_private_extension &optional;
	end_user_addr: gtp_end_user_addr &optional;
};

type gtp_update_pdp_ctx_response_elements: record {
	cause:          gtp_cause;
	recovery:       gtp_recovery &optional;
	data1:          gtp_teid1 &optional;
	cp:             gtp_teid_control_plane &optional;
	charging_id:    gtp_charging_id &optional;
	cp_addr:        gtp_gsn_addr &optional;
	user_addr:      gtp_gsn_addr &optional;
	qos_prof:       gtp_qos_profile &optional;
	charge_gateway: gtp_charging_gateway_addr &optional;
	ext:            gtp_private_extension &optional;
};

type gtp_delete_pdp_ctx_request_elements: record {
	teardown_ind: gtp_teardown_ind &optional;
	nsapi:        gtp_nsapi;
	ext:          gtp_private_extension &optional;
};

type gtp_delete_pdp_ctx_response_elements: record {
	cause: gtp_cause;
	ext:   gtp_private_extension &optional;
};

## Definition of "secondary filters". A secondary filter is a BPF filter given
## as index in this table. For each such filter, the corresponding event is
## raised for all matching packets.
global secondary_filters: table[string] of event(filter: string, pkt: pkt_hdr)
	&redef;

## Maximum length of payload passed to discarder functions.
##
## .. bro:see:: discarder_check_tcp discarder_check_udp discarder_check_icmp
##    discarder_check_ip
global discarder_maxlen = 128 &redef;

## Function for skipping packets based on their IP header. If defined, this
## function will be called for all IP packets before Bro performs any further
## analysis. If the function signals to discard a packet, no further processing
## will be performed on it.
##
## p: The IP header of the considered packet.
##
## Returns: True if the packet should not be analyzed any further.
##
## .. bro:see:: discarder_check_tcp discarder_check_udp discarder_check_icmp
##    discarder_maxlen
##
## .. note:: This is very low-level functionality and potentially expensive.
##    Avoid using it.
global discarder_check_ip: function(p: pkt_hdr): bool;

## Function for skipping packets based on their TCP header. If defined, this
## function will be called for all TCP packets before Bro performs any further
## analysis. If the function signals to discard a packet, no further processing
## will be performed on it.
##
## p: The IP and TCP headers of the considered packet.
##
## d: Up to :bro:see:`discarder_maxlen` bytes of the TCP payload.
##
## Returns: True if the packet should not be analyzed any further.
##
## .. bro:see:: discarder_check_ip discarder_check_udp discarder_check_icmp
##    discarder_maxlen
##
## .. note:: This is very low-level functionality and potentially expensive.
##    Avoid using it.
global discarder_check_tcp: function(p: pkt_hdr, d: string): bool;

## Function for skipping packets based on their UDP header. If defined, this
## function will be called for all UDP packets before Bro performs any further
## analysis. If the function signals to discard a packet, no further processing
## will be performed on it.
##
## p: The IP and UDP headers of the considered packet.
##
## d: Up to :bro:see:`discarder_maxlen` bytes of the UDP payload.
##
## Returns: True if the packet should not be analyzed any further.
##
## .. bro:see:: discarder_check_ip discarder_check_tcp discarder_check_icmp
##    discarder_maxlen
##
## .. note:: This is very low-level functionality and potentially expensive.
##    Avoid using it.
global discarder_check_udp: function(p: pkt_hdr, d: string): bool;

## Function for skipping packets based on their ICMP header. If defined, this
## function will be called for all ICMP packets before Bro performs any further
## analysis. If the function signals to discard a packet, no further processing
## will be performed on it.
##
## p: The IP and ICMP headers of the considered packet.
##
## Returns: True if the packet should not be analyzed any further.
##
## .. bro:see:: discarder_check_ip discarder_check_tcp discarder_check_udp
##    discarder_maxlen
##
## .. note:: This is very low-level functionality and potentially expensive.
##    Avoid using it.
global discarder_check_icmp: function(p: pkt_hdr): bool;

## Bro's watchdog interval.
const watchdog_interval = 10 sec &redef;

## The maximum number of timers to expire after processing each new
## packet.  The value trades off spreading out the timer expiration load
## with possibly having to hold state longer.  A value of 0 means
## "process all expired timers with each new packet".
const max_timer_expires = 300 &redef;

## With a similar trade-off, this gives the number of remote events
## to process in a batch before interleaving other activity.
const max_remote_events_processed = 10 &redef;

# These need to match the definitions in Login.h.
#
# .. bro:see:: get_login_state
#
# todo:: use enum to make them autodoc'able
const LOGIN_STATE_AUTHENTICATE = 0;	# Trying to authenticate.
const LOGIN_STATE_LOGGED_IN = 1;	# Successful authentication.
const LOGIN_STATE_SKIP = 2;	# Skip any further processing.
const LOGIN_STATE_CONFUSED = 3;	# We're confused.

# It would be nice to replace these function definitions with some
# form of parameterized types.

## Returns minimum of two ``double`` values.
##
## a: First value.
## b: Second value.
##
## Returns: The minimum of *a* and *b*.
function min_double(a: double, b: double): double { return a < b ? a : b; }

## Returns maximum of two ``double`` values.
##
## a: First value.
## b: Second value.
##
## Returns: The maximum of *a* and *b*.
function max_double(a: double, b: double): double { return a > b ? a : b; }

## Returns minimum of two ``interval`` values.
##
## a: First value.
## b: Second value.
##
## Returns: The minimum of *a* and *b*.
function min_interval(a: interval, b: interval): interval { return a < b ? a : b; }

## Returns maximum of two ``interval`` values.
##
## a: First value.
## b: Second value.
##
## Returns: The maximum of *a* and *b*.
function max_interval(a: interval, b: interval): interval { return a > b ? a : b; }

## Returns minimum of two ``count`` values.
##
## a: First value.
## b: Second value.
##
## Returns: The minimum of *a* and *b*.
function min_count(a: count, b: count): count { return a < b ? a : b; }

## Returns maximum of two ``count`` values.
##
## a: First value.
## b: Second value.
##
## Returns: The maximum of *a* and *b*.
function max_count(a: count, b: count): count { return a > b ? a : b; }

## TODO.
global skip_authentication: set[string] &redef;

## TODO.
global direct_login_prompts: set[string] &redef;

## TODO.
global login_prompts: set[string] &redef;

## TODO.
global login_non_failure_msgs: set[string] &redef;

## TODO.
global login_failure_msgs: set[string] &redef;

## TODO.
global login_success_msgs: set[string] &redef;

## TODO.
global login_timeouts: set[string] &redef;

## A MIME header key/value pair.
##
## .. bro:see:: mime_header_list http_all_headers mime_all_headers mime_one_header
type mime_header_rec: record {
	name: string;	##< The header name.
	value: string;	##< The header value.
};

## A list of MIME headers.
##
## .. bro:see:: mime_header_rec http_all_headers mime_all_headers
type mime_header_list: table[count] of mime_header_rec;

## The length of MIME data segments delivered to handlers of
## :bro:see:`mime_segment_data`.
##
## .. bro:see:: mime_segment_data mime_segment_overlap_length
global mime_segment_length = 1024 &redef;

## The number of bytes of overlap between successive segments passed to
## :bro:see:`mime_segment_data`.
global mime_segment_overlap_length = 0 &redef;

## An RPC portmapper mapping.
##
## .. bro:see:: pm_mappings
type pm_mapping: record {
	program: count;	##< The RPC program.
	version: count;	##< The program version.
	p: port;	##< The port.
};

## Table of RPC portmapper mappings.
##
## .. bro:see:: pm_request_dump
type pm_mappings: table[count] of pm_mapping;

## An RPC portmapper request.
##
## .. bro:see:: pm_attempt_getport pm_request_getport
type pm_port_request: record {
	program: count;	##< The RPC program.
	version: count;	##< The program version.
	is_tcp: bool;	##< True if using TCP.
};

## An RPC portmapper *callit* request.
##
## .. bro:see:: pm_attempt_callit pm_request_callit
type pm_callit_request: record {
	program: count;	##< The RPC program.
	version: count;	##< The program version.
	proc: count;	##< The procedure being called.
	arg_size: count;	##< The size of the argument.
};

# See const.bif
# const RPC_SUCCESS = 0;
# const RPC_PROG_UNAVAIL = 1;
# const RPC_PROG_MISMATCH = 2;
# const RPC_PROC_UNAVAIL = 3;
# const RPC_GARBAGE_ARGS = 4;
# const RPC_SYSTEM_ERR = 5;
# const RPC_TIMEOUT = 6;
# const RPC_AUTH_ERROR = 7;
# const RPC_UNKNOWN_ERROR = 8;

## Mapping of numerical RPC status codes to readable messages.
##
## .. bro:see:: pm_attempt_callit pm_attempt_dump pm_attempt_getport
##    pm_attempt_null pm_attempt_set pm_attempt_unset rpc_dialogue rpc_reply
const RPC_status = {
	[RPC_SUCCESS] = "ok",
	[RPC_PROG_UNAVAIL] = "prog unavail",
	[RPC_PROG_MISMATCH] = "mismatch",
	[RPC_PROC_UNAVAIL] = "proc unavail",
	[RPC_GARBAGE_ARGS] = "garbage args",
	[RPC_SYSTEM_ERR] = "system err",
	[RPC_TIMEOUT] = "timeout",
	[RPC_AUTH_ERROR] = "auth error",
	[RPC_UNKNOWN_ERROR] = "unknown"
};

module NFS3;

export {
	## If true, :bro:see:`nfs_proc_read` and :bro:see:`nfs_proc_write`
	## events return the file data that has been read/written.
	##
	## .. bro:see:: NFS3::return_data_max NFS3::return_data_first_only
	const return_data = F &redef;

	## If :bro:id:`NFS3::return_data` is true, how much data should be
	## returned at most.
	const return_data_max = 512 &redef;

	## If :bro:id:`NFS3::return_data` is true, whether to *only* return data
	## if the read or write offset is 0, i.e., only return data for the
	## beginning of the file.
	const return_data_first_only = T &redef;

	## Record summarizing the general results and status of NFSv3
	## request/reply pairs.
	##
	## Note that when *rpc_stat* or *nfs_stat* indicates not successful,
	## the reply record passed to the corresponding event will be empty and
	## contain uninitialized fields, so don't use it. Also note that time
	## and duration values might not be fully accurate. For TCP, we record
	## times when the corresponding chunk of data is delivered to the
	## analyzer. Depending on the reassembler, this might be well after the
	## first packet of the request was received.
	##
	## .. bro:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup
	##    nfs_proc_mkdir nfs_proc_not_implemented nfs_proc_null
	##    nfs_proc_read nfs_proc_readdir nfs_proc_readlink nfs_proc_remove
	##    nfs_proc_rmdir nfs_proc_write nfs_reply_status
	type info_t: record {
		## The RPC status.
		rpc_stat: rpc_status;
		## The NFS status.
		nfs_stat: status_t;
		## The start time of the request.
		req_start: time;
		## The duration of the request.
		req_dur: interval;
		## The length in bytes of the request.
		req_len: count;
		## The start time of the reply.
		rep_start: time;
		## The duration of the reply.
		rep_dur: interval;
		## The length in bytes of the reply.
		rep_len: count;
	};

	## NFS file attributes. Field names are based on RFC 1813.
	##
	## .. bro:see:: nfs_proc_getattr
	type fattr_t: record {
		ftype: file_type_t;	##< File type.
		mode: count;	##< Mode
		nlink: count;	##< Number of links.
		uid: count;	##< User ID.
		gid: count;	##< Group ID.
		size: count;	##< Size.
		used: count;	##< TODO.
		rdev1: count;	##< TODO.
		rdev2: count;	##< TODO.
		fsid: count;	##< TODO.
		fileid: count;	##< TODO.
		atime: time;	##< Time of last access.
		mtime: time;	##< Time of last modification.
		ctime: time;	##< Time of creation.
	};

	## NFS *readdir* arguments.
	##
	## .. bro:see:: nfs_proc_readdir
	type diropargs_t : record {
		dirfh: string;	##< The file handle of the directory.
		fname: string;	##< The name of the file we are interested in.
	};

	## NFS lookup reply. If the lookup failed, *dir_attr* may be set. If the
	## lookup succeeded, *fh* is always set and *obj_attr* and *dir_attr*
	## may be set.
	##
	## .. bro:see:: nfs_proc_lookup
	type lookup_reply_t: record {
		fh: string &optional;	##< File handle of object looked up.
		obj_attr: fattr_t &optional;	##< Optional attributes associated w/ file
		dir_attr: fattr_t &optional;	##< Optional attributes associated w/ dir.
	};

	## NFS *read* arguments.
	##
	## .. bro:see:: nfs_proc_read
	type readargs_t: record {
		fh: string;	##< File handle to read from.
		offset: count;	##< Offset in file.
		size: count;	##< Number of bytes to read.
	};

	## NFS *read* reply. If the lookup fails, *attr* may be set. If the
	## lookup succeeds, *attr* may be set and all other fields are set.
	type read_reply_t: record {
		attr: fattr_t &optional;	##< Attributes.
		size: count &optional;	##< Number of bytes read.
		eof: bool &optional;	##< Sid the read end at EOF.
		data: string &optional;	##< The actual data; not yet implemented.
	};

	## NFS *readline* reply. If the request fails, *attr* may be set. If the
	## request succeeds, *attr* may be set and all other fields are set.
	##
	## .. bro:see:: nfs_proc_readlink
	type readlink_reply_t: record {
		attr: fattr_t &optional;	##< Attributes.
		nfspath: string &optional;	##< Contents of the symlink; in general a pathname as text.
	};

	## NFS *write* arguments.
	##
	## .. bro:see:: nfs_proc_write
	type writeargs_t: record {
		fh: string;	##< File handle to write to.
		offset: count;	##< Offset in file.
		size: count;	##< Number of bytes to write.
		stable: stable_how_t;	##< How and when data is commited.
		data: string &optional;	##< The actual data; not implemented yet.
	};

	## NFS *wcc* attributes.
	##
	## .. bro:see:: NFS3::write_reply_t
	type wcc_attr_t: record {
		size: count;	##< The size.
		atime: time;	##< Access time.
		mtime: time;	##< Modification time.
	};

	## NFS *write* reply. If the request fails, *pre|post* attr may be set.
	## If the request succeeds, *pre|post* attr may be set and all other
	## fields are set.
	##
	## .. bro:see:: nfs_proc_write
	type write_reply_t: record {
		preattr: wcc_attr_t &optional;	##< Pre operation attributes.
		postattr: fattr_t &optional;	##< Post operation attributes.
		size: count &optional;	##< Size.
		commited: stable_how_t &optional;	##< TODO.
		verf: count &optional;	##< Write verifier cookie.
	};

	## NFS reply for *create*, *mkdir*, and *symlink*. If the proc
	## failed, *dir_\*_attr* may be set. If the proc succeeded, *fh* and the
	## *attr*'s may be set. Note: no guarantee that *fh* is set after
	## success.
	##
	## .. bro:see:: nfs_proc_create nfs_proc_mkdir
	type newobj_reply_t: record {
		fh: string &optional;	##< File handle of object created.
		obj_attr: fattr_t &optional;	##< Optional attributes associated w/ new object.
		dir_pre_attr: wcc_attr_t &optional;	##< Optional attributes associated w/ dir.
		dir_post_attr: fattr_t &optional;	##< Optional attributes associated w/ dir.
	};

	## NFS reply for *remove*, *rmdir*. Corresponds to *wcc_data* in the spec.
	##
	## .. bro:see:: nfs_proc_remove nfs_proc_rmdir
	type delobj_reply_t: record {
		dir_pre_attr: wcc_attr_t &optional;	##< Optional attributes associated w/ dir.
		dir_post_attr: fattr_t &optional;	##< Optional attributes associated w/ dir.
	};

	## NFS *readdir* arguments. Used for both *readdir* and *readdirplus*.
	##
	## .. bro:see:: nfs_proc_readdir
	type readdirargs_t: record {
		isplus: bool;	##< Is this a readdirplus request?
		dirfh: string;	##< The directory filehandle.
		cookie: count;	##< Cookie / pos in dir; 0 for first call.
		cookieverf: count;	##< The cookie verifier.
		dircount: count;	##< "count" field for readdir; maxcount otherwise (in bytes).
		maxcount: count &optional;	##< Only used for readdirplus. in bytes.
	};

	## NFS *direntry*.  *fh* and *attr* are used for *readdirplus*. However,
	## even for *readdirplus* they may not be filled out.
	##
	## .. bro:see:: NFS3::direntry_vec_t NFS3::readdir_reply_t
	type direntry_t: record {
		fileid: count;	##< E.g., inode number.
		fname:  string;	##< Filename.
		cookie: count;	##< Cookie value.
		attr: fattr_t &optional;	##< *readdirplus*: the *fh* attributes for the entry.
		fh: string &optional;	##< *readdirplus*: the *fh* for the entry
	};

	## Vector of NFS *direntry*.
	##
	## .. bro:see:: NFS3::readdir_reply_t
	type direntry_vec_t: vector of direntry_t;

	## NFS *readdir* reply. Used for *readdir* and *readdirplus*. If an is
	## returned, *dir_attr* might be set. On success, *dir_attr* may be set,
	## all others must be set.
	type readdir_reply_t: record {
		isplus: bool;	##< True if the reply for a *readdirplus* request.
		dir_attr: fattr_t &optional;	##< Directory attributes.
		cookieverf: count &optional;	##< TODO.
		entries: direntry_vec_t &optional;	##< Returned directory entries.
		eof: bool;	##< If true, no more entries in directory.
	};

	## NFS *fsstat*.
	type fsstat_t: record {
		attrs: fattr_t &optional;	##< Attributes.
		tbytes: double;	##< TODO.
		fbytes: double;	##< TODO.
		abytes: double;	##< TODO.
		tfiles: double;	##< TODO.
		ffiles: double;	##< TODO.
		afiles: double;	##< TODO.
		invarsec: interval;	##< TODO.
	};
} # end export

module Threading;

export {
	## The heartbeat interval used by the threading framework.
	## Changing this should usually not be necessary and will break
	## several tests.
	const heartbeat_interval = 1.0 secs &redef;
}

module GLOBAL;

## An NTP message.
##
## .. bro:see:: ntp_message
type ntp_msg: record {
	id: count;	##< Message ID.
	code: count;	##< Message code.
	stratum: count;	##< Stratum.
	poll: count;	##< Poll.
	precision: int;	##< Precision.
	distance: interval;	##< Distance.
	dispersion: interval;	##< Dispersion.
	ref_t: time;	##< Reference time.
	originate_t: time;	##< Originating time.
	receive_t: time;	##< Receive time.
	xmit_t: time;	##< Send time.
};


## Maps SMB command numbers to descriptive names.
global samba_cmds: table[count] of string &redef
			&default = function(c: count): string
				{ return fmt("samba-unknown-%d", c); };

## An SMB command header.
##
## .. bro:see:: smb_com_close smb_com_generic_andx smb_com_logoff_andx
##    smb_com_negotiate smb_com_negotiate_response smb_com_nt_create_andx
##    smb_com_read_andx smb_com_setup_andx smb_com_trans_mailslot
##    smb_com_trans_pipe smb_com_trans_rap smb_com_transaction
##    smb_com_transaction2 smb_com_tree_connect_andx smb_com_tree_disconnect
##    smb_com_write_andx smb_error smb_get_dfs_referral smb_message
type smb_hdr : record {
	command: count;	##< The command number (see :bro:see:`samba_cmds`).
	status: count;	##< The status code.
	flags: count;	##< Flag set 1.
	flags2: count;	##< Flag set 2.
	tid: count;	##< TODO.
	pid: count;	##< Process ID.
	uid: count;	##< User ID.
	mid: count;	##< TODO.
};

## An SMB transaction.
##
## .. bro:see:: smb_com_trans_mailslot smb_com_trans_pipe smb_com_trans_rap
##    smb_com_transaction smb_com_transaction2
type smb_trans : record {
	word_count: count;	##< TODO.
	total_param_count: count;	##< TODO.
	total_data_count: count;	##< TODO.
	max_param_count: count;	##< TODO.
	max_data_count: count;	##< TODO.
	max_setup_count: count;	##< TODO.
#	flags: count;
#	timeout: count;
	param_count: count;	##< TODO.
	param_offset: count;	##< TODO.
	data_count: count;	##< TODO.
	data_offset: count;	##< TODO.
	setup_count: count;	##< TODO.
	setup0: count;	##< TODO.
	setup1: count;	##< TODO.
	setup2: count;	##< TODO.
	setup3: count;	##< TODO.
	byte_count: count;	##< TODO.
	parameters: string;	##< TODO.
};


## SMB transaction data.
##
## .. bro:see:: smb_com_trans_mailslot smb_com_trans_pipe smb_com_trans_rap
##    smb_com_transaction smb_com_transaction2
##
## .. todo:: Should this really be a record type?
type smb_trans_data : record {
	data : string;	##< The transaction's data.
};

## Deprecated.
##
## .. todo:: Remove. It's still declared internally but doesn't seem  used anywhere
##    else.
type smb_tree_connect : record {
	flags: count;
	password: string;
	path: string;
	service: string;
};

## Deprecated.
##
## .. todo:: Remove. It's still declared internally but doesn't seem  used anywhere
##    else.
type smb_negotiate : table[count] of string;

## A list of router addresses offered by a DHCP server.
##
## .. bro:see:: dhcp_ack dhcp_offer
type dhcp_router_list: table[count] of addr;

## A DHCP message.
##
## .. bro:see:: dhcp_ack dhcp_decline dhcp_discover dhcp_inform dhcp_nak
##    dhcp_offer dhcp_release dhcp_request
type dhcp_msg: record {
	op: count;	##< Message OP code. 1 = BOOTREQUEST, 2 = BOOTREPLY
	m_type: count;	##< The type of DHCP message.
	xid: count;	##< Transaction ID of a DHCP session.
	h_addr: string;	##< Hardware address of the client.
	ciaddr: addr;	##< Original IP address of the client.
	yiaddr: addr;	##< IP address assigned to the client.
};

## A DNS message.
##
## .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
##    dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
##    dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end
##    dns_message dns_query_reply dns_rejected dns_request
type dns_msg: record {
	id: count;	##< Transaction ID.

	opcode: count;	##< Operation code.
	rcode: count;	##< Return code.

	QR: bool;	##< Query response flag.
	AA: bool;	##< Authoritative answer flag.
	TC: bool;	##< Truncated packet flag.
	RD: bool;	##< Recursion desired flag.
	RA: bool;	##< Recursion available flag.
	Z: count;	##< TODO.

	num_queries: count;	##< Number of query records.
	num_answers: count;	##< Number of answer records.
	num_auth: count;	##< Number of authoritative records.
	num_addl: count;	##< Number of additional records.
};

## A DNS SOA record.
##
## .. bro:see:: dns_SOA_reply
type dns_soa: record {
	mname: string;	##< Primary source of data for zone.
	rname: string;	##< Mailbox for responsible person.
	serial: count;	##< Version number of zone.
	refresh: interval;	##< Seconds before refreshing.
	retry: interval;	##< How long before retrying failed refresh.
	expire: interval;	##< When zone no longer authoritative.
	minimum: interval;	##< Minimum TTL to use when exporting.
};

## An additional DNS EDNS record.
##
## .. bro:see:: dns_EDNS_addl
type dns_edns_additional: record {
	query: string;	##< Query.
	qtype: count;	##< Query type.
	t: count;	##< TODO.
	payload_size: count;	##< TODO.
	extended_rcode: count;	##< Extended return code.
	version: count;	##< Version.
	z_field: count;	##< TODO.
	TTL: interval;	##< Time-to-live.
	is_query: count;	##< TODO.
};

## An additional DNS TSIG record.
##
## bro:see:: dns_TSIG_addl
type dns_tsig_additional: record {
	query: string;	##< Query.
	qtype: count;	##< Query type.
	alg_name: string;	##< Algorithm name.
	sig: string;	##< Signature.
	time_signed: time;	##< Time when signed.
	fudge: time;	##< TODO.
	orig_id: count;	##< TODO.
	rr_error: count;	##< TODO.
	is_query: count;	##< TODO.
};

# DNS answer types.
#
# .. bro:see:: dns_answerr
#
# todo:: use enum to make them autodoc'able
const DNS_QUERY = 0;	##< A query. This shouldn't occur, just for completeness.
const DNS_ANS = 1;	##< An answer record.
const DNS_AUTH = 2;	##< An authoritative record.
const DNS_ADDL = 3;	##< An additional record.

## The general part of a DNS reply.
##
## .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_HINFO_reply
##    dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply
##    dns_TXT_reply dns_WKS_reply
type dns_answer: record {
	## Answer type. One of :bro:see:`DNS_QUERY`, :bro:see:`DNS_ANS`,
	## :bro:see:`DNS_AUTH` and :bro:see:`DNS_ADDL`.
	answer_type: count;
	query: string;	##< Query.
	qtype: count;	##< Query type.
	qclass: count;	##< Query class.
	TTL: interval;	##< Time-to-live.
};

## For DNS servers in these sets, omit processing the AUTH records they include
## in their replies.
##
## .. bro:see:: dns_skip_all_auth dns_skip_addl
global dns_skip_auth: set[addr] &redef;

## For DNS servers in these sets, omit processing the ADDL records they include
## in their replies.
##
## .. bro:see:: dns_skip_all_addl dns_skip_auth
global dns_skip_addl: set[addr] &redef;

## If true, all DNS AUTH records are skipped.
##
## .. bro:see:: dns_skip_all_addl dns_skip_auth
global dns_skip_all_auth = T &redef;

## If true, all DNS ADDL records are skipped.
##
## .. bro:see:: dns_skip_all_auth dns_skip_addl
global dns_skip_all_addl = T &redef;

## If a DNS request includes more than this many queries, assume it's non-DNS
## traffic and do not process it.  Set to 0 to turn off this functionality.
global dns_max_queries = 5;

## HTTP session statistics.
##
## .. bro:see:: http_stats
type http_stats_rec: record {
	num_requests: count;	##< Number of requests.
	num_replies: count;	##< Number of replies.
	request_version: double;	##< HTTP version of the requests.
	reply_version: double;	##< HTTP Version of the replies.
};

## HTTP message statistics.
##
## .. bro:see:: http_message_done
type http_message_stat: record {
	## When the request/reply line was complete.
	start: time;
	## Whether the message was interrupted.
	interrupted: bool;
	## Reason phrase if interrupted.
	finish_msg: string;
	## Length of body processed (before finished/interrupted).
	body_length: count;
	## Total length of gaps within *body_length*.
	content_gap_length: count;
	## Length of headers (including the req/reply line, but not CR/LF's).
	header_length: count;
};

## Maximum number of HTTP entity data delivered to events. The amount of data
## can be limited for better performance, zero disables truncation.
##
## .. bro:see:: http_entity_data skip_http_entity_data skip_http_data
global http_entity_data_delivery_size = 1500 &redef;

## Skip HTTP data for performance considerations. The skipped
## portion will not go through TCP reassembly.
##
## .. bro:see:: http_entity_data skip_http_entity_data http_entity_data_delivery_size
const skip_http_data = F &redef;

## Maximum length of HTTP URIs passed to events. Longer ones will be truncated
## to prevent over-long URIs (usually sent by worms) from slowing down event
## processing.  A value of -1 means "do not truncate".
##
## .. bro:see:: http_request
const truncate_http_URI = -1 &redef;

## IRC join information.
##
## .. bro:see:: irc_join_list
type irc_join_info: record {
	nick: string;
	channel: string;
	password: string;
	usermode: string;
};

## Set of IRC join information.
##
## .. bro:see:: irc_join_message
type irc_join_list: set[irc_join_info];

## Deprecated.
##
## .. todo:: Remove. It's still declared internally but doesn't seem  used anywhere
##    else.
global irc_servers : set[addr] &redef;

## Internal to the stepping stone detector.
const stp_delta: interval &redef;

## Internal to the stepping stone detector.
const stp_idle_min: interval &redef;

## Internal to the stepping stone detector.
global stp_skip_src: set[addr] &redef;

## Deprecated.
const interconn_min_interarrival: interval &redef;

## Deprecated.
const interconn_max_interarrival: interval &redef;

## Deprecated.
const interconn_max_keystroke_pkt_size: count &redef;

## Deprecated.
const interconn_default_pkt_size: count &redef;

## Deprecated.
const interconn_stat_period: interval &redef;

## Deprecated.
const interconn_stat_backoff: double &redef;

## Deprecated.
type interconn_endp_stats: record {
	num_pkts: count;
	num_keystrokes_two_in_row: count;
	num_normal_interarrivals: count;
	num_8k0_pkts: count;
	num_8k4_pkts: count;
	is_partial: bool;
	num_bytes: count;
	num_7bit_ascii: count;
	num_lines: count;
	num_normal_lines: count;
};

## Deprecated.
const backdoor_stat_period: interval &redef;

## Deprecated.
const backdoor_stat_backoff: double &redef;

## Deprecated.
type backdoor_endp_stats: record {
	is_partial: bool;
	num_pkts: count;
	num_8k0_pkts: count;
	num_8k4_pkts: count;
	num_lines: count;
	num_normal_lines: count;
	num_bytes: count;
	num_7bit_ascii: count;
};

## Description of a signature match.
##
## .. bro:see:: signature_match
type signature_state: record {
	sig_id:       string;	##< ID of the matching signature.
	conn:         connection;	##< Matching connection.
	is_orig:      bool;	##< True if matching endpoint is originator.
	payload_size: count;	##< Payload size of the first matching packet of current endpoint.
};

# Deprecated.
#
# .. todo:: This type is no longer used. Remove any reference of this from the
#    core.
type software_version: record {
	major: int;
	minor: int;
	minor2: int;
	addl: string;
};

# Deprecated.
#
# .. todo:: This type is no longer used. Remove any reference of this from the
#    core.
type software: record {
	name: string;
	version: software_version;
};

## Quality of passive fingerprinting matches.
##
## .. bro:see:: OS_version
type OS_version_inference: enum {
	direct_inference,	##< TODO.
	generic_inference,	##< TODO.
	fuzzy_inference,	##< TODO.
};

## Passive fingerprinting match.
##
## .. bro:see:: OS_version_found
type OS_version: record {
	genre: string;	##< Linux, Windows, AIX, ...
	detail: string;	##< Kernel version or such.
	dist: count;	##< How far is the host away from the sensor (TTL)?.
	match_type: OS_version_inference;	##< Quality of the match.
};

## Defines for which subnets we should do passive fingerprinting.
##
## .. bro:see:: OS_version_found
global generate_OS_version_event: set[subnet] &redef;

# Type used to report load samples via :bro:see:`load_sample`. For now, it's a
# set of names (event names, source file names, and perhaps ``<source file, line
# number>``), which were seen during the sample.
type load_sample_info: set[string];

## ID for NetFlow header. This is primarily a means to sort together NetFlow
## headers and flow records at the script level.
type nfheader_id: record {
	## Name of the NetFlow file (e.g., ``netflow.dat``) or the receiving
	## socket address (e.g., ``127.0.0.1:5555``), or an explicit name if
	## specified to ``-y`` or ``-Y``.
	rcvr_id: string;
	## A serial number, ignoring any overflows.
	pdu_id: count;
};

## A NetFlow v5 header.
##
## .. bro:see:: netflow_v5_header
type nf_v5_header: record {
	h_id: nfheader_id;	##< ID for sorting.
	cnt: count;	##< TODO.
	sysuptime: interval;	##< Router's uptime.
	exporttime: time;	##< When the data was exported.
	flow_seq: count;	##< Sequence number.
	eng_type: count;	##< Engine type.
	eng_id: count;	##< Engine ID.
	sample_int: count;	##< Sampling interval.
	exporter: addr;	##< Exporter address.
};

## A NetFlow v5 record.
##
## .. bro:see:: netflow_v5_record
type nf_v5_record: record {
	h_id: nfheader_id;	##< ID for sorting.
	id: conn_id;	##< Connection ID.
	nexthop: addr;	##< Address of next hop.
	input: count;	##< Input interface.
	output: count;	##< Output interface.
	pkts: count;	##< Number of packets.
	octets: count;	##< Number of bytes.
	first: time;	##< Timestamp of first packet.
	last: time;	##< Timestamp of last packet.
	tcpflag_fin: bool;	##< FIN flag for TCP flows.
	tcpflag_syn: bool;	##< SYN flag for TCP flows.
	tcpflag_rst: bool;	##< RST flag for TCP flows.
	tcpflag_psh: bool;	##< PSH flag for TCP flows.
	tcpflag_ack: bool;	##< ACK flag for TCP flows.
	tcpflag_urg: bool;	##< URG flag for TCP flows.
	proto: count;	##< IP protocol.
	tos: count;	##< Type of service.
	src_as: count;	##< Source AS.
	dst_as: count;	##< Destination AS.
	src_mask: count;	##< Source mask.
	dst_mask: count;	##< Destination mask.
};


## A BitTorrent peer.
##
## .. bro:see:: bittorrent_peer_set
type bittorrent_peer: record {
	h: addr;	##< The peer's address.
	p: port;	##< The peer's port.
};

## A set of BitTorrent peers.
##
## .. bro:see:: bt_tracker_response
type bittorrent_peer_set: set[bittorrent_peer];

## BitTorrent "benc" value. Note that "benc" = Bencode ("Bee-Encode"), per
## http://en.wikipedia.org/wiki/Bencode.
##
## .. bro:see:: bittorrent_benc_dir
type bittorrent_benc_value: record {
	i: int &optional;	##< TODO.
	s: string &optional;	##< TODO.
	d: string &optional;	##< TODO.
	l: string &optional;	##< TODO.
};

## A table of BitTorrent "benc" values.
##
## .. bro:see:: bt_tracker_response
type bittorrent_benc_dir: table[string] of bittorrent_benc_value;

## Header table type used by BitTorrent analyzer.
##
## .. bro:see:: bt_tracker_request bt_tracker_response
##    bt_tracker_response_not_ok
type bt_tracker_headers: table[string] of string;

type ModbusCoils: vector of bool;
type ModbusRegisters: vector of count;

type ModbusHeaders: record {
	tid:           count;
	pid:           count;
	uid:           count;
	function_code: count;
};

module Unified2;
export {
	type Unified2::IDSEvent: record {
		sensor_id:          count;
		event_id:           count;
		ts:                 time;
		signature_id:       count;
		generator_id:       count;
		signature_revision: count;
		classification_id:  count;
		priority_id:        count;
		src_ip:             addr;
		dst_ip:             addr;
		src_p:              port;
		dst_p:              port;
		impact_flag:        count;
		impact:             count;
		blocked:            count;
		## Not available in "legacy" IDS events.
		mpls_label:         count  &optional;
		## Not available in "legacy" IDS events.
		vlan_id:            count  &optional;
		## Only available in "legacy" IDS events.
		packet_action:      count  &optional;
	};

	type Unified2::Packet: record {
		sensor_id:    count;
		event_id:     count;
		event_second: count;
		packet_ts:    time;
		link_type:    count;
		data:         string;
	};
}

module X509;
export {
	type Certificate: record {
		version: count;	##< Version number.
		serial: string;	##< Serial number.
		subject: string;	##< Subject.
		issuer: string;	##< Issuer.
		not_valid_before: time;	##< Timestamp before when certificate is not valid.
		not_valid_after: time;	##< Timestamp after when certificate is not valid.
		key_alg: string;	##< Name of the key algorithm
		sig_alg: string;	##< Name of the signature algorithm
		key_type: string &optional;	##< Key type, if key parseable by openssl (either rsa, dsa or ec)
		key_length: count &optional;	##< Key length in bits
		exponent: string &optional;	##< Exponent, if RSA-certificate
		curve: string &optional;	##< Curve, if EC-certificate
	} &log;

	type Extension: record {
		name: string;	##< Long name of extension. oid if name not known
		short_name: string &optional;	##< Short name of extension if known
		oid: string;	##< Oid of extension
		critical: bool;	##< True if extension is critical
		value: string;	##< Extension content parsed to string for known extensions. Raw data otherwise.
	};

	type BasicConstraints: record {
		ca: bool;	##< CA flag set?
		path_len: count &optional;	##< Maximum path length
	} &log;

	type SubjectAlternativeName: record {
		dns: string_vec &optional &log;	##< List of DNS entries in SAN
		uri: string_vec &optional &log;	##< List of URI entries in SAN
		email: string_vec &optional &log;	##< List of email entries in SAN
		ip: addr_vec &optional &log;	##< List of IP entries in SAN
		other_fields: bool;	##< True if the certificate contained other, not recognized or parsed name fields
	};

	## Result of an X509 certificate chain verification
	type Result: record {
		## OpenSSL result code
		result:	count;
		## Result as string
		result_string: string;
		## References to the final certificate chain, if verification successful. End-host certificate is first.
		chain_certs: vector of opaque of x509 &optional;
	};
}

module SOCKS;
export {
	## This record is for a SOCKS client or server to provide either a
	## name or an address to represent a desired or established connection.
	type Address: record {
		host: addr   &optional;
		name: string &optional;
	} &log;
}
module GLOBAL;

@load base/bif/plugins/Bro_SNMP.types.bif

module SNMP;
export {
	## The top-level message data structure of an SNMPv1 datagram, not
	## including the PDU data.  See :rfc:`1157`.
	type SNMP::HeaderV1: record {
		community: string;
	};

	## The top-level message data structure of an SNMPv2 datagram, not
	## including the PDU data.  See :rfc:`1901`.
	type SNMP::HeaderV2: record {
		community: string;
	};

	## The ``ScopedPduData`` data structure of an SNMPv3 datagram, not
	## including the PDU data (i.e. just the "context" fields).
	## See :rfc:`3412`.
	type SNMP::ScopedPDU_Context: record {
		engine_id: string;
		name:      string;
	};

	## The top-level message data structure of an SNMPv3 datagram, not
	## including the PDU data.  See :rfc:`3412`.
	type SNMP::HeaderV3: record {
		id:              count;
		max_size:        count;
		flags:           count;
		auth_flag:       bool;
		priv_flag:       bool;
		reportable_flag: bool;
		security_model:  count;
		security_params: string;
		pdu_context:     SNMP::ScopedPDU_Context &optional;
	};

	## A generic SNMP header data structure that may include data from
	## any version of SNMP.  The value of the ``version`` field
	## determines what header field is initialized.
	type SNMP::Header: record {
		version: count;
		v1:      SNMP::HeaderV1 &optional; ##< Set when ``version`` is 0.
		v2:      SNMP::HeaderV2 &optional; ##< Set when ``version`` is 1.
		v3:      SNMP::HeaderV3 &optional; ##< Set when ``version`` is 3.
	};

	## A generic SNMP object value, that may include any of the
	## valid ``ObjectSyntax`` values from :rfc:`1155` or :rfc:`3416`.
	## The value is decoded whenever possible and assigned to
	## the appropriate field, which can be determined from the value
	## of the ``tag`` field.  For tags that can't be mapped to an
	## appropriate type, the ``octets`` field holds the BER encoded
	## ASN.1 content if there is any (though, ``octets`` is may also
	## be used for other tags such as OCTET STRINGS or Opaque).  Null
	## values will only have their corresponding tag value set.
	type SNMP::ObjectValue: record {
		tag:      count;
		oid:      string &optional;
		signed:   int    &optional;
		unsigned: count  &optional;
		address:  addr   &optional;
		octets:   string &optional;
	};

	# These aren't an enum because it's easier to type fields as count.
	# That way don't have to deal with type conversion, plus doesn't
	# mislead that these are the only valid tag values (it's just the set
	# of known tags).
	const SNMP::OBJ_INTEGER_TAG       : count = 0x02; ##< Signed 64-bit integer.
	const SNMP::OBJ_OCTETSTRING_TAG   : count = 0x04; ##< An octet string.
	const SNMP::OBJ_UNSPECIFIED_TAG   : count = 0x05; ##< A NULL value.
	const SNMP::OBJ_OID_TAG           : count = 0x06; ##< An Object Identifier.
	const SNMP::OBJ_IPADDRESS_TAG     : count = 0x40; ##< An IP address.
	const SNMP::OBJ_COUNTER32_TAG     : count = 0x41; ##< Unsigned 32-bit integer.
	const SNMP::OBJ_UNSIGNED32_TAG    : count = 0x42; ##< Unsigned 32-bit integer.
	const SNMP::OBJ_TIMETICKS_TAG     : count = 0x43; ##< Unsigned 32-bit integer.
	const SNMP::OBJ_OPAQUE_TAG        : count = 0x44; ##< An octet string.
	const SNMP::OBJ_COUNTER64_TAG     : count = 0x46; ##< Unsigned 64-bit integer.
	const SNMP::OBJ_NOSUCHOBJECT_TAG  : count = 0x80; ##< A NULL value.
	const SNMP::OBJ_NOSUCHINSTANCE_TAG: count = 0x81; ##< A NULL value.
	const SNMP::OBJ_ENDOFMIBVIEW_TAG  : count = 0x82; ##< A NULL value.

	## The ``VarBind`` data structure from either :rfc:`1157` or
	## :rfc:`3416`, which maps an Object Identifier to a value.
	type SNMP::Binding: record {
		oid:   string;
		value: SNMP::ObjectValue;
	};

	## A ``VarBindList`` data structure from either :rfc:`1157` or :rfc:`3416`.
	## A sequences of :bro:see:`SNMP::Binding`, which maps an OIDs to values.
	type SNMP::Bindings: vector of SNMP::Binding;

	## A ``PDU`` data structure from either :rfc:`1157` or :rfc:`3416`.
	type SNMP::PDU: record {
		request_id:   int;
		error_status: int;
		error_index:  int;
		bindings:     SNMP::Bindings;
	};

	## A ``Trap-PDU`` data structure from :rfc:`1157`.
	type SNMP::TrapPDU: record {
		enterprise:    string;
		agent:         addr;
		generic_trap:  int;
		specific_trap: int;
		time_stamp:    count;
		bindings:      SNMP::Bindings;
	};

	## A ``BulkPDU`` data structure from :rfc:`3416`.
	type SNMP::BulkPDU: record {
		request_id:      int;
		non_repeaters:   count;
		max_repititions: count;
		bindings:        SNMP::Bindings;
	};
}

module GLOBAL;

@load base/bif/event.bif

## BPF filter the user has set via the -f command line options. Empty if none.
const cmd_line_bpf_filter = "" &redef;

## The maximum number of open files to keep cached at a given time.
## If set to zero, this is automatically determined by inspecting
## the current/maximum limit on open files for the process.
const max_files_in_cache = 0 &redef;

## Deprecated.
const log_rotate_interval = 0 sec &redef;

## Deprecated.
const log_rotate_base_time = "0:00" &redef;

## Deprecated.
const log_max_size = 0.0 &redef;

## Deprecated.
const log_encryption_key = "<undefined>" &redef;

## Write profiling info into this file in regular intervals. The easiest way to
## activate profiling is loading :doc:`/scripts/policy/misc/profiling.bro`.
##
## .. bro:see:: profiling_interval expensive_profiling_multiple segment_profiling
global profiling_file: file &redef;

## Update interval for profiling (0 disables).  The easiest way to activate
## profiling is loading  :doc:`/scripts/policy/misc/profiling.bro`.
##
## .. bro:see:: profiling_file expensive_profiling_multiple segment_profiling
const profiling_interval = 0 secs &redef;

## Multiples of :bro:see:`profiling_interval` at which (more expensive) memory
## profiling is done (0 disables).
##
## .. bro:see:: profiling_interval profiling_file segment_profiling
const expensive_profiling_multiple = 0 &redef;

## If true, then write segment profiling information (very high volume!)
## in addition to profiling statistics.
##
## .. bro:see:: profiling_interval expensive_profiling_multiple profiling_file
const segment_profiling = F &redef;

## Output modes for packet profiling information.
##
## .. bro:see:: pkt_profile_mode pkt_profile_freq pkt_profile_file
type pkt_profile_modes: enum {
	PKT_PROFILE_MODE_NONE,	##< No output.
	PKT_PROFILE_MODE_SECS,	##< Output every :bro:see:`pkt_profile_freq` seconds.
	PKT_PROFILE_MODE_PKTS,	##< Output every :bro:see:`pkt_profile_freq` packets.
	PKT_PROFILE_MODE_BYTES,	##< Output every :bro:see:`pkt_profile_freq` bytes.
};

## Output mode for packet profiling information.
##
## .. bro:see:: pkt_profile_modes pkt_profile_freq pkt_profile_file
const pkt_profile_mode = PKT_PROFILE_MODE_NONE &redef;

## Frequency associated with packet profiling.
##
## .. bro:see:: pkt_profile_modes pkt_profile_mode pkt_profile_file
const pkt_profile_freq = 0.0 &redef;

## File where packet profiles are logged.
##
## .. bro:see:: pkt_profile_modes pkt_profile_freq pkt_profile_mode
global pkt_profile_file: file &redef;

## Rate at which to generate :bro:see:`load_sample` events. As all
## events, the event is only generated if you've also defined a
## :bro:see:`load_sample` handler.  Units are inverse number of packets; e.g.,
## a value of 20 means "roughly one in every 20 packets".
##
## .. bro:see:: load_sample
global load_sample_freq = 20 &redef;

## Rate at which to generate :bro:see:`gap_report` events assessing to what
## degree the measurement process appears to exhibit loss.
##
## .. bro:see:: gap_report
const gap_report_freq = 1.0 sec &redef;

## Whether to attempt to automatically detect SYN/FIN/RST-filtered trace
## and not report missing segments for such connections.
## If this is enabled, then missing data at the end of connections may not
## be reported via :bro:see:`content_gap`.
const detect_filtered_trace = F &redef;

## Whether we want :bro:see:`content_gap` and :bro:see:`gap_report` for partial
## connections. A connection is partial if it is missing a full handshake. Note
## that gap reports for partial connections might not be reliable.
##
## .. bro:see:: content_gap gap_report partial_connection
const report_gaps_for_partial = F &redef;

## Flag to prevent Bro from exiting automatically when input is exhausted.
## Normally Bro terminates when all packet sources have gone dry
## and communication isn't enabled. If this flag is set, Bro's main loop will
## instead keep idling until :bro:see:`terminate` is explicitly called.
##
## This is mainly for testing purposes when termination behaviour needs to be
## controlled for reproducing results.
const exit_only_after_terminate = F &redef;

## The CA certificate file to authorize remote Bros/Broccolis.
##
## .. bro:see:: ssl_private_key ssl_passphrase
const ssl_ca_certificate = "<undefined>" &redef;

## File containing our private key and our certificate.
##
## .. bro:see:: ssl_ca_certificate ssl_passphrase
const ssl_private_key = "<undefined>" &redef;

## The passphrase for our private key. Keeping this undefined
## causes Bro to prompt for the passphrase.
##
## .. bro:see:: ssl_private_key ssl_ca_certificate
const ssl_passphrase = "<undefined>" &redef;

## Default mode for Bro's user-space dynamic packet filter. If true, packets
## that aren't explicitly allowed through, are dropped from any further
## processing.
##
## .. note:: This is not the BPF packet filter but an additional dynamic filter
##    that Bro optionally applies just before normal processing starts.
##
## .. bro:see:: install_dst_addr_filter install_dst_net_filter
##    install_src_addr_filter install_src_net_filter  uninstall_dst_addr_filter
##    uninstall_dst_net_filter uninstall_src_addr_filter uninstall_src_net_filter
const packet_filter_default = F &redef;

## Maximum size of regular expression groups for signature matching.
const sig_max_group_size = 50 &redef;

## Deprecated. No longer functional.
const enable_syslog = F &redef;

## Description transmitted to remote communication peers for identification.
const peer_description = "bro" &redef;

## If true, broadcast events received from one peer to all other peers.
##
## .. bro:see:: forward_remote_state_changes
##
## .. note:: This option is only temporary and will disappear once we get a
##    more sophisticated script-level communication framework.
const forward_remote_events = F &redef;

## If true, broadcast state updates received from one peer to all other peers.
##
## .. bro:see:: forward_remote_events
##
## .. note:: This option is only temporary and will disappear once we get a
##    more sophisticated script-level communication framework.
const forward_remote_state_changes = F &redef;

## Place-holder constant indicating "no peer".
const PEER_ID_NONE = 0;

# Signature payload pattern types.
# todo:: use enum to help autodoc
# todo:: Still used?
#const SIG_PATTERN_PAYLOAD = 0;
#const SIG_PATTERN_HTTP = 1;
#const SIG_PATTERN_FTP = 2;
#const SIG_PATTERN_FINGER = 3;

# Deprecated.
# todo::Should use the new logging framework directly.
const REMOTE_LOG_INFO = 1;	##< Deprecated.
const REMOTE_LOG_ERROR = 2;	##< Deprecated.

# Source of logging messages from the communication framework.
# todo:: these should go into an enum to make them autodoc'able.
const REMOTE_SRC_CHILD = 1;	##< Message from the child process.
const REMOTE_SRC_PARENT = 2;	##< Message from the parent process.
const REMOTE_SRC_SCRIPT = 3;	##< Message from a policy script.

## Synchronize trace processing at a regular basis in pseudo-realtime mode.
##
## .. bro:see:: remote_trace_sync_peers
const remote_trace_sync_interval = 0 secs &redef;

## Number of peers across which to synchronize trace processing in
## pseudo-realtime mode.
##
## .. bro:see:: remote_trace_sync_interval
const remote_trace_sync_peers = 0 &redef;

## Whether for :bro:attr:`&synchronized` state to send the old value as a
## consistency check.
const remote_check_sync_consistency = F &redef;

## Reassemble the beginning of all TCP connections before doing
## signature matching. Enabling this provides more accurate matching at the
## expense of CPU cycles.
##
## .. bro:see:: dpd_buffer_size
##    dpd_match_only_beginning dpd_ignore_ports
##
## .. note:: Despite the name, this option affects *all* signature matching, not
##    only signatures used for dynamic protocol detection.
const dpd_reassemble_first_packets = T &redef;

## Size of per-connection buffer used for dynamic protocol detection. For each
## connection, Bro buffers this initial amount of payload in memory so that
## complete protocol analysis can start even after the initial packets have
## already passed through (i.e., when a DPD signature matches only later).
## However, once the buffer is full, data is deleted and lost to analyzers that
## are activated afterwards. Then only analyzers that can deal with partial
## connections will be able to analyze the session.
##
## .. bro:see:: dpd_reassemble_first_packets dpd_match_only_beginning
##    dpd_ignore_ports
const dpd_buffer_size = 1024 &redef;

## If true, stops signature matching if :bro:see:`dpd_buffer_size` has been
## reached.
##
## .. bro:see:: dpd_reassemble_first_packets dpd_buffer_size
##    dpd_ignore_ports
##
## .. note:: Despite the name, this option affects *all* signature matching, not
##    only signatures used for dynamic protocol detection.
const dpd_match_only_beginning = T &redef;

## If true, don't consider any ports for deciding which protocol analyzer to
## use.
##
## .. bro:see:: dpd_reassemble_first_packets dpd_buffer_size
##    dpd_match_only_beginning
const dpd_ignore_ports = F &redef;

## Ports which the core considers being likely used by servers. For ports in
## this set, it may heuristically decide to flip the direction of the
## connection if it misses the initial handshake.
const likely_server_ports: set[port] &redef;

## Per-incident timer managers are drained after this amount of inactivity.
const timer_mgr_inactivity_timeout = 1 min &redef;

## If true, output profiling for Time-Machine queries.
const time_machine_profiling = F &redef;

## If true, warns about unused event handlers at startup.
const check_for_unused_event_handlers = F &redef;

# If true, dumps all invoked event handlers at startup.
# todo::Still used?
# const dump_used_event_handlers = F &redef;

## Deprecated.
const suppress_local_output = F &redef;

## Holds the filename of the trace file given with ``-w`` (empty if none).
##
## .. bro:see:: record_all_packets
const trace_output_file = "";

## If a trace file is given with ``-w``, dump *all* packets seen by Bro into it.
## By default, Bro applies (very few) heuristics to reduce the volume. A side
## effect of setting this to true is that we can write the packets out before we
## actually process them, which can be helpful for debugging in case the
## analysis triggers a crash.
##
## .. bro:see:: trace_output_file
const record_all_packets = F &redef;

## Ignore certain TCP retransmissions for :bro:see:`conn_stats`.  Some
## connections (e.g., SSH) retransmit the acknowledged last byte to keep the
## connection alive. If *ignore_keep_alive_rexmit* is set to true, such
## retransmissions will be excluded in the rexmit counter in
## :bro:see:`conn_stats`.
##
## .. bro:see:: conn_stats
const ignore_keep_alive_rexmit = F &redef;

module JSON;
export {
	type TimestampFormat: enum {
		## Timestamps will be formatted as UNIX epoch doubles.  This is
		## the format that Bro typically writes out timestamps.
		TS_EPOCH,
		## Timestamps will be formatted as unsigned integers that
		## represent the number of milliseconds since the UNIX
		## epoch.
		TS_MILLIS,
		## Timestamps will be formatted in the ISO8601 DateTime format.
		## Subseconds are also included which isn't actually part of the
		## standard but most consumers that parse ISO8601 seem to be able
		## to cope with that.
		TS_ISO8601,
	};
}

module Tunnel;
export {
	## The maximum depth of a tunnel to decapsulate until giving up.
	## Setting this to zero will disable all types of tunnel decapsulation.
	const max_depth: count = 2 &redef;

	## Toggle whether to do IPv{4,6}-in-IPv{4,6} decapsulation.
	const enable_ip = T &redef;

	## Toggle whether to do IPv{4,6}-in-AYIYA decapsulation.
	const enable_ayiya = T &redef;

	## Toggle whether to do IPv6-in-Teredo decapsulation.
	const enable_teredo = T &redef;

	## Toggle whether to do GTPv1 decapsulation.
	const enable_gtpv1 = T &redef;

	## Toggle whether to do GRE decapsulation.
	const enable_gre = T &redef;

	## With this option set, the Teredo analysis will first check to see if
	## other protocol analyzers have confirmed that they think they're
	## parsing the right protocol and only continue with Teredo tunnel
	## decapsulation if nothing else has yet confirmed.  This can help
	## reduce false positives of UDP traffic (e.g. DNS) that also happens
	## to have a valid Teredo encapsulation.
	const yielding_teredo_decapsulation = T &redef;

	## With this set, the Teredo analyzer waits until it sees both sides
	## of a connection using a valid Teredo encapsulation before issuing
	## a :bro:see:`protocol_confirmation`.  If it's false, the first
	## occurrence of a packet with valid Teredo encapsulation causes a
	## confirmation.  Both cases are still subject to effects of
	## :bro:see:`Tunnel::yielding_teredo_decapsulation`.
	const delay_teredo_confirmation = T &redef;

	## With this set, the GTP analyzer waits until the most-recent upflow
	## and downflow packets are a valid GTPv1 encapsulation before
	## issuing :bro:see:`protocol_confirmation`.  If it's false, the
	## first occurrence of a packet with valid GTPv1 encapsulation causes
	## confirmation.  Since the same inner connection can be carried
	## differing outer upflow/downflow connections, setting to false
	## may work better.
	const delay_gtp_confirmation = F &redef;

	## How often to cleanup internal state for inactive IP tunnels
	## (includes GRE tunnels).
	const ip_tunnel_timeout = 24hrs &redef;
} # end export
module GLOBAL;

module Reporter;
export {
	## Tunable for sending reporter info messages to STDERR.  The option to
	## turn it off is presented here in case Bro is being run by some
	## external harness and shouldn't output anything to the console.
	const info_to_stderr = T &redef;

	## Tunable for sending reporter warning messages to STDERR.  The option
	## to turn it off is presented here in case Bro is being run by some
	## external harness and shouldn't output anything to the console.
	const warnings_to_stderr = T &redef;

	## Tunable for sending reporter error messages to STDERR.  The option to
	## turn it off is presented here in case Bro is being run by some
	## external harness and shouldn't output anything to the console.
	const errors_to_stderr = T &redef;
}
module GLOBAL;

## Number of bytes per packet to capture from live interfaces.
const snaplen = 8192 &redef;

## Seed for hashes computed internally for probabilistic data structures. Using
## the same value here will make the hashes compatible between independent Bro
## instances. If left unset, Bro will use a temporary local seed.
const global_hash_seed: string = "" &redef;

## Number of bits in UIDs that are generated to identify connections and
## files.  The larger the value, the more confidence in UID uniqueness.
## The maximum is currently 128 bits.
const bits_per_uid: count = 96 &redef;

# Load BiFs defined by plugins.
@load base/bif/plugins

# Load these frameworks here because they use fairly deep integration with
# BiFs and script-land defined types.
@load base/frameworks/logging
@load base/frameworks/input
@load base/frameworks/analyzer
@load base/frameworks/files

@load base/bif
