module PacketAnalyzer;

@load base/frameworks/analyzer/main.zeek

export {
	## Registers a set of well-known ports for an analyzer. If a future
	## connection on one of these ports is seen, the analyzer will be
	## automatically assigned to parsing it. The function *adds* to all ports
	## already registered, it doesn't replace them.
	##
	## tag: The tag of the analyzer.
	##
	## ports: The set of well-known ports to associate with the analyzer.
	##
	## Returns: True if the ports were successfully registered.
	global register_for_ports: function(parent: PacketAnalyzer::Tag,
	                                    child: PacketAnalyzer::Tag,
	                                    ports: set[port]) : bool;

	## Registers an individual well-known port for an analyzer. If a future
	## connection on this port is seen, the analyzer will be automatically
	## assigned to parsing it. The function *adds* to all ports already
	## registered, it doesn't replace them.
	##
	## tag: The tag of the analyzer.
	##
	## p: The well-known port to associate with the analyzer.
	##
	## Returns: True if the port was successfully registered.
	global register_for_port: function(parent: PacketAnalyzer::Tag,
	                                   child: PacketAnalyzer::Tag,
	                                   p: port) : bool;
}

function register_for_ports(parent: PacketAnalyzer::Tag,
                            child: PacketAnalyzer::Tag,
                            ports: set[port]) : bool
	{
	local rc = T;

	for ( p in ports )
		{
		if ( ! register_for_port(parent, child, p) )
			rc = F;
		}

	return rc;
	}

function register_for_port(parent: PacketAnalyzer::Tag,
                           child: PacketAnalyzer::Tag,
                           p: port) : bool
	{
	register_packet_analyzer(parent, port_to_count(p), child);

	if ( child !in Analyzer::ports )
		Analyzer::ports[child] = set();

	add Analyzer::ports[child][p];
	return T;
	}
