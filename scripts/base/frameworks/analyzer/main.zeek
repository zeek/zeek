##! Framework for managing Zeek's protocol analyzers.
##!
##! The analyzer framework allows to dynamically enable or disable analyzers, as
##! well as to manage the well-known ports which automatically activate a
##! particular analyzer for new connections.
##!
##! Protocol analyzers are identified by unique tags of type
##! :zeek:type:`Analyzer::Tag`, such as :zeek:enum:`Analyzer::ANALYZER_HTTP`.
##! These tags are defined internally by
##! the analyzers themselves, and documented in their analyzer-specific
##! description along with the events that they generate.
##!
##! Analyzer tags are also inserted into a global :zeek:type:`AllAnalyzers::Tag` enum
##! type. This type contains duplicates of all of the :zeek:type:`Analyzer::Tag`,
##! :zeek:type:`PacketAnalyzer::Tag` and :zeek:type:`Files::Tag` enum values
##! and can be used for arguments to function/hook/event definitions where they
##! need to handle any analyzer type. See :zeek:id:`Analyzer::register_for_ports`
##! for an example.

@load base/frameworks/packet-filter/utils

module Analyzer;

export {
	## If true, all available analyzers are initially disabled at startup.
	## One can then selectively enable them with
	## :zeek:id:`Analyzer::enable_analyzer`.
	global disable_all = F &redef;

	## Enables an analyzer. Once enabled, the analyzer may be used for analysis
	## of future connections as decided by Zeek's dynamic protocol detection.
	##
	## tag: The tag of the analyzer to enable.
	##
	## Returns: True if the analyzer was successfully enabled.
	global enable_analyzer: function(tag: AllAnalyzers::Tag) : bool;

	## Disables an analyzer. Once disabled, the analyzer will not be used
	## further for analysis of future connections.
	##
	## tag: The tag of the analyzer to disable.
	##
	## Returns: True if the analyzer was successfully disabled.
	global disable_analyzer: function(tag: AllAnalyzers::Tag) : bool;

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
	global register_for_ports: function(tag: Analyzer::Tag, ports: set[port]) : bool;

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
	global register_for_port: function(tag: Analyzer::Tag, p: port) : bool;

	## Returns a set of all well-known ports currently registered for a
	## specific analyzer.
	##
	## tag: The tag of the analyzer.
	##
	## Returns: The set of ports.
	global registered_ports: function(tag: AllAnalyzers::Tag) : set[port];

	## Returns a table of all ports-to-analyzer mappings currently registered.
	##
	## Returns: A table mapping each analyzer to the set of ports
	##          registered for it.
	global all_registered_ports: function() : table[AllAnalyzers::Tag] of set[port];

	## Translates an analyzer type to a string with the analyzer's name.
	##
	## tag: The analyzer tag.
	##
	## Returns: The analyzer name corresponding to the tag.
	global name: function(tag: Analyzer::Tag) : string;

	## Check whether the given analyzer name exists.
	##
	## This can be used before calling :zeek:see:`Analyzer::get_tag` to
	## verify that the given name as string is a valid analyzer name.
	##
	## name: The analyzer name.
	##
	## Returns: True if the given name is a valid analyzer, else false.
	global has_tag: function(name: string): bool;

	## Translates an analyzer's name to a tag enum value.
	##
	## name: The analyzer name.
	##
	## Returns: The analyzer tag corresponding to the name.
	global get_tag: function(name: string): Analyzer::Tag;

	## Schedules an analyzer for a future connection originating from a
	## given IP address and port.
	##
	## orig: The IP address originating a connection in the future.
	##       0.0.0.0 can be used as a wildcard to match any originator address.
	##
	## resp: The IP address responding to a connection from *orig*.
	##
	## resp_p: The destination port at *resp*.
	##
	## analyzer: The analyzer ID.
	##
	## tout: A timeout interval after which the scheduling request will be
	##       discarded if the connection has not yet been seen.
	##
	## Returns: True if successful.
	global schedule_analyzer: function(orig: addr, resp: addr, resp_p: port,
	                                   analyzer: Analyzer::Tag, tout: interval) : bool;

	## Automatically creates a BPF filter for the specified protocol based
	## on the data supplied for the protocol through the
	## :zeek:see:`Analyzer::register_for_ports` function.
	##
	## tag: The analyzer tag.
	##
	## Returns: BPF filter string.
	global analyzer_to_bpf: function(tag: Analyzer::Tag): string;

	## Create a BPF filter which matches all of the ports defined
	## by the various protocol analysis scripts as "registered ports"
	## for the protocol.
	global get_bpf: function(): string;

	## A set of analyzers to disable by default at startup. The default set
	## contains legacy analyzers that are no longer supported.
	global disabled_analyzers: set[AllAnalyzers::Tag] = {
		ANALYZER_TCPSTATS,
	} &redef;

	## A table of ports mapped to analyzers that handle those ports. This is
	## used by BPF filtering and DPD. Session analyzers can add to this using
	## Analyzer::register_for_port(s) and packet analyzers can add to this
	## using PacketAnalyzer::register_for_port(s).
	global ports: table[AllAnalyzers::Tag] of set[port];

	## A set of protocol, packet or file analyzer tags requested to
	## be enabled during startup.
	##
	## By default, all analyzers in Zeek are enabled. When all analyzers
	## are disabled through :zeek:see:`Analyzer::disable_all`, this set
	## set allows to record analyzers to be enabled during Zeek startup.
	##
	## This set can be added to via :zeek:see:`redef`.
	global requested_analyzers: set[AllAnalyzers::Tag] = {} &redef;
}

@load base/bif/analyzer.bif
@load base/bif/file_analysis.bif
@load base/bif/packet_analysis.bif

event zeek_init() &priority=5
	{
	if ( disable_all )
		__disable_all_analyzers();

	for ( a in disabled_analyzers )
		disable_analyzer(a);
	}

event zeek_init() &priority=-5
	{
	for ( a in requested_analyzers )
		Analyzer::enable_analyzer(a);
	}

function enable_analyzer(tag: AllAnalyzers::Tag) : bool
	{
	if ( is_packet_analyzer(tag) )
		return PacketAnalyzer::__enable_analyzer(tag);

	if ( is_file_analyzer(tag) )
		return Files::__enable_analyzer(tag);

	return __enable_analyzer(tag);
	}

function disable_analyzer(tag: AllAnalyzers::Tag) : bool
	{
	if ( is_packet_analyzer(tag) )
		return PacketAnalyzer::__disable_analyzer(tag);

	if ( is_file_analyzer(tag) )
		return Files::__disable_analyzer(tag);

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

function registered_ports(tag: AllAnalyzers::Tag) : set[port]
	{
	return tag in ports ? ports[tag] : set();
	}

function all_registered_ports(): table[AllAnalyzers::Tag] of set[port]
	{
	return ports;
	}

function name(atype: AllAnalyzers::Tag) : string
	{
	return __name(atype);
	}

function has_tag(name: string): bool
	{
	return __has_tag(name);
	}

function get_tag(name: string): AllAnalyzers::Tag
	{
	return __tag(name);
	}

function schedule_analyzer(orig: addr, resp: addr, resp_p: port,
			   analyzer: Analyzer::Tag, tout: interval) : bool
	{
	return __schedule_analyzer(orig, resp, resp_p, analyzer, tout);
	}

function analyzer_to_bpf(tag: Analyzer::Tag): string
	{
	# Return an empty string if an undefined analyzer was given.
	if ( tag !in ports )
		return "";

	local output = "";
	for ( p in ports[tag] )
		output = PacketFilter::combine_filters(output, "or", PacketFilter::port_to_bpf(p));
	return output;
	}

function get_bpf(): string
	{
	local output = "";
	for ( tag in ports )
		{
		output = PacketFilter::combine_filters(output, "or", analyzer_to_bpf(tag));
		}
	return output;
	}
