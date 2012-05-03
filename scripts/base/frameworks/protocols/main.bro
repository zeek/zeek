
@load base/frameworks/packet-filter/utils

module Protocols;

export {
	
	const common_ports: table[string] of set[port] = {} &redef;

	## Automatically creates a BPF filter for the specified protocol based
	## on the data supplied for the protocol in the :bro:id:`common_ports`
	## variable.
	##
	## protocol: A string representation for a protocol, e.g. "HTTP"
	##
	## Returns: BPF filter string.
	global protocol_to_bpf: function(protocol: string): string;
	
	## Create a BPF filter which matches all of the ports defined 
	## by the various protocol analysis scripts as "common ports"
	## for the protocol.
	global to_bpf: function(): string;
	
	## Maps between human readable protocol identifiers (like "HTTP")
	## and the internal Bro representation for an analyzer (like ANALYZER_HTTP).
	## This is typically fully populated by the base protocol analyzer scripts.
	const analyzer_map: table[string] of set[AnalyzerTag] = {} &redef;
}

event bro_init() &priority=10
	{
	for ( proto in common_ports )
		{
		for ( p in common_ports[proto] )
			dpd_analyzer_ports[p] = analyzer_map[proto];
		for ( a in analyzer_map[proto] )
			dpd_config[a] = [$ports=common_ports[proto]];
		}
	}

function protocol_to_bpf(protocol: string): string
	{
	# Return an empty string if an undefined protocol was given.
	if ( protocol !in common_ports )
		return "";
	
	local output = "";
	for ( one_port in common_ports[protocol] )
		output = PacketFilter::combine_filters(output, "or", PacketFilter::port_to_bpf(one_port));
	return output;
	}
	
function to_bpf(): string
	{
	local output = "";
	for ( p in common_ports )
		output = PacketFilter::combine_filters(output, "or", protocol_to_bpf(p));
	return output;
	}
