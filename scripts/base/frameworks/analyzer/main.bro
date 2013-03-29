
module Analyzer;

# Analyzer::Tag is defined in types.bif, and automatically extended by plugins
# as they are loaded.

export {
	## XXX.
	global enable_analyzer: function(tag: Analyzer::Tag) : bool;

	## XXX.
	global disable_analyzer: function(tag: Analyzer::Tag) : bool;

	## XXX.
	global register_for_ports: function(tag: Analyzer::Tag, ports: set[port]) : bool;

	## XXX.
	global register_for_port: function(tag: Analyzer::Tag, p: port) : bool;

	## XXX.
	global registered_ports: function(tag: Analyzer::Tag) : set[port];

	## XXX
	global all_registered_ports: function() : table[Analyzer::Tag] of set[port]; 

	## Translate an analyzer type to an ASCII string.
	##
	## atype: The analyzer tag.
	##
	## Returns: The analyzer *aid* as string.
	global name: function(atype: Analyzer::Tag) : string;

	## Schedules an analyzer for a future connection from a given IP address and
	## port. The function ignores the scheduling request if the connection did
	## not occur within the specified time interval.
	##
	## orig: The IP address originating a connection in the future.
	##
	## resp: The IP address responding to a connection from *orig*.
	##
	## resp_p: The destination port at *resp*.
	##
	## analyzer: The analyzer ID.
	##
	## tout: The timeout interval after which to ignore the scheduling request.
	##
	## Returns: True if succesful.
	global expect_connection: function(orig: addr, resp: addr, resp_p: port,
					   analyzer: Analyzer::Tag, tout: interval) : bool;

	## Analyzers to disable at startup.
	global disabled_analyzers: set[Analyzer::Tag] = {
		ANALYZER_INTERCONN,
		ANALYZER_STEPPINGSTONE,
		ANALYZER_BACKDOOR,
		ANALYZER_TCPSTATS,
	}

	&redef;
}

@load base/bif/analyzer.bif

global ports: table[Analyzer::Tag] of set[port];

event bro_init()
	{
	for ( a in disabled_analyzers )
		disable_analyzer(a);
	}

function enable_analyzer(tag: Analyzer::Tag) : bool
	{
	return __enable_analyzer(tag);
	}

function disable_analyzer(tag: Analyzer::Tag) : bool
	{
	return __disable_analyzer(tag);
	}

function register_for_ports(tag: Analyzer::Tag, ports: set[port]) : bool
	{
	local rc = T;
	
	for ( p in ports ) 
		{
		if ( ! register_for_port(tag, p) )
			rc = F;
		}

	return rc;
	}

function register_for_port(tag: Analyzer::Tag, p: port) : bool
	{
	if ( ! __register_for_port(tag, p) )
		return F;

	if ( tag !in ports )
		ports[tag] = set();
	
	add ports[tag][p];
	return T;
	}

function registered_ports(tag: Analyzer::Tag) : set[port]
	{
	return tag in ports ? ports[tag] : set();
	}

function all_registered_ports(): table[Analyzer::Tag] of set[port]
	{
	return ports;
	}

function name(atype: Analyzer::Tag) : string
	{
	return __name(atype);
	}

function expect_connection(orig: addr, resp: addr, resp_p: port,
			   analyzer: Analyzer::Tag, tout: interval) : bool
	{
	return __expect_connection(orig, resp, resp_p, analyzer, tout);
	}

