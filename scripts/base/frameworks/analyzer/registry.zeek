##! Analyzer registry tracking the relationship between protocol analyzers
##! and logs or features they provide.
##!
##! Sketching out things.


module Analyzer::Registry;

export {
	type AnalyzerClass: enum {
		PROTOCOL,
		FILE,
		PACKET,
	};

	type LogOptions: record {
		## Idea: Tag / group to disable when logging is disabled.
		## Optional/optimization.
		event_groups: set[string] &default=set();
	};

	## Infos about a log related to an analyzer.
	type AnalyzerLogInfo: record {
		id: Log::ID;
		options: LogOptions;
	};

	# express dependency between analyzers? requires? depends_on? ...
	type RelationshipOptions: record {
		# ...
	};

	## Information / Metadata attached to a given protocol or file analyzer.
	## Alternative name: AnalyzerDescription ?
	type AnalyzerInfo: record {
		atype: AllAnalyzers::Tag;
		aclass: AnalyzerClass;
		logs: table[Log::ID] of AnalyzerLogInfo &default=table();

		## Relationships between analyzers.
		##
		## Idea: IRC relates to IRC_DATA, FTP relates to FTP_DATA.
		## Mostly for informational purposes, but could consider
		## when disabling IRC we could disable IRC_DATA, too.
		##
		## Though probably won't make a practical difference.
		relates_to: set[AllAnalyzers::Tag] &default=set();

		# XXX: Only set on enumerate or lookup() as not updated
		#      dynamically within the repository.
		enabled: bool &optional;
	};

	# --- Registration functions used by analyzer scripts
	#

	## For the given analyzer, register a log with optional LogOptions
	global register_log: function(atype: AllAnalyzers::Tag, log_id: Log::ID,
	                              options: LogOptions &default=LogOptions());

	## Relationships between analyzers
	global register_relationship: function(atype: AllAnalyzers::Tag,
	                                       atype2: AllAnalyzers::Tag,
	                                       options: RelationshipOptions &default=RelationshipOptions());


	# --- User functions

	## Enumerate all available AnalyzerInfo records.
	global enumerate: function(): vector of AnalyzerInfo;


	## Disable all registered logs for the given analyzer.
	##
	## Optimized: Disable events related to this log stream if provided
	## Naive: Call Log::disable_stream(Log::ID)
	## TBD: Or do both, actually.
	global disable_analyzer_logs: function(atype: AllAnalyzers::Tag);

	## Disable just one specific log of the given analyzer.
	##
	## Optimized: Disable events related to this log stream if provided
	## Naive: Call Log::disable_stream(Log::ID)
	## TBD: Or do both, actually.
	global disable_analyzer_log: function(atype: AllAnalyzers::Tag, id: Log::ID);

	## Disable a log, possibly also disabling involved event handlers
	## if any were registered with the registry.
	global disable_log: function(id: Log::ID);

	const non_analyzer_log_streams: set[Log::ID] = { } &redef;
}

global analyzer_infos: table[AllAnalyzers::Tag] of AnalyzerInfo;

# Logs pointing back at analyzer_info records.
global log_infos: table[Log::ID] of AnalyzerInfo;


function analyzer_class(atype: AllAnalyzers::Tag): AnalyzerClass
	{
	if ( is_protocol_analyzer(atype) )
		return PROTOCOL;
	else if ( is_file_analyzer(atype) )
		return FILE;
	else if ( is_packet_analyzer(atype) )
		return PACKET;

	Reporter::error(fmt("Unknown analyzer class: %s", atype));
	return PROTOCOL;
	}

function analyzer_is_enabled(atype: AllAnalyzers::Tag): bool
	{
	if ( is_protocol_analyzer(atype) )
		{
		return Analyzer::analyzer_enabled(atype);
		}
	else if ( is_packet_analyzer(atype) )
		# Status: It's complicated. Currently, packet analyzers
		#         don't have a generic "disable/enable" setting.
		#         Some tunnel analyzers have it in an ad-hoc (ayiya, vxlan),
		#         but not open-coding for now. Assume enabled.
		#
		#         See also, https://github.com/zeek/zeek/issues/2399
		return T;
	else if ( is_file_analyzer(atype) )
	    return Files::analyzer_enabled(atype);

	Reporter::error(fmt("Unknown analyzer class: %s", atype));
	return F;
	}

function register_analyzer(atype: AllAnalyzers::Tag): AnalyzerInfo
	{
	if ( atype !in analyzer_infos )
		analyzer_infos[atype] = AnalyzerInfo($atype=atype, $aclass=analyzer_class(atype));

	return analyzer_infos[atype];
	}

function register_log(atype: AllAnalyzers::Tag, id: Log::ID, options: LogOptions)
	{
	register_analyzer(atype);
	analyzer_infos[atype]$logs[id] = AnalyzerLogInfo($id=id, $options=options);

	log_infos[id] = analyzer_infos[atype];
	}

function register_relationship(atype: AllAnalyzers::Tag, atype2: AllAnalyzers::Tag,
                               options: RelationshipOptions)
	{
	register_analyzer(atype);
	register_analyzer(atype2);
	add analyzer_infos[atype]$relates_to[atype2];
	}

function enumerate(): vector of AnalyzerInfo
	{
	local values: vector of AnalyzerInfo;
	for ( _, ai in analyzer_infos )
		{
		local aic = copy(ai);
		aic$enabled = analyzer_is_enabled(ai$atype);
		values += aic;
		}

	return values;
	}


# Register all analyzers based on the AllAnalyzers::Tag for which we don't
# have an explicit registration.
event zeek_init() &priority=-1000
	{
	for ( k, v in global_ids() )
		{
		if ( /AllAnalyzers::.+_.*/ != k )
			next;

		# Mangle the AllAnalyzers tag first to the actual names,
		# then lookup the tag.
		# AllAnalyzers::FILES_ANALYZER_PE -> pe
		# AllAnalyzers::PACKETANALYZER_ANALYZER_VXLAN -> vxlan
		# AllAnalyzers::ANALYZER_ANALYZER_SMB -> smb
		#
		# XXX: Analyzer::get_tag() works for protocol, files and packet
		#      analyzers, but one never defines what kind/class it is.
		#      The assumption seems to be there's no naming overlap.
		local mangled = gsub(k, /AllAnalyzers::(ANALYZER|PACKETANALYZER|FILES)_/, "");
		local name = to_lower(split_string1(mangled, /_/)[1]);

		local atype = Analyzer::get_tag(name);

		if ( atype !in analyzer_infos )
			{
			# Skip the packet ones for now.
			if ( analyzer_class(atype) != PACKET )
				print "Analyzer not registered", atype;

			register_analyzer(atype);
			}
		}
	}

# Log untracked/un-registered streams
event zeek_init() &priority=-2000
	{

	# Using Log::all_streams would be nice as someone might have
	# disabled a log by now, but oh well.
	for ( id, __ in Log::active_streams )
		{
		if ( id !in log_infos  && id !in non_analyzer_log_streams )
			print "Untracked stream", id;
		}
	}


# Minimal example showing how analyzers would register information about
# themselves.

@load base/protocols/dns
@load base/protocols/irc
@load base/protocols/http
@load base/protocols/syslog
@load base/protocols/mqtt
@load base/protocols/imap
@load base/frameworks/notice/weird

# Protocols in policy
@load protocols/mqtt


@load misc/detect-traceroute
@load misc/capture-loss

module Examples;


# Analyzers scripts can add information about themselves to the registry.
# For example, which logs are produced for a given analyzer.
#
# This is a rather analyzer central approach: What if there are logs that
# are based on multiple analyzers. Is this then the right approach?
#
# Examples of non-analyzer logs
# * weird.log
# * notice.log
# * reporter.log
# ...


# Mostly here to stop logging these, but also provides a summary of log
# streams that are not directly attached to a specific analyzer.
redef Analyzer::Registry::non_analyzer_log_streams += { Broker::LOG };
redef Analyzer::Registry::non_analyzer_log_streams += { Cluster::LOG };
redef Analyzer::Registry::non_analyzer_log_streams += { CaptureLoss::LOG };
redef Analyzer::Registry::non_analyzer_log_streams += { Config::LOG };
redef Analyzer::Registry::non_analyzer_log_streams += { DPD::LOG };
redef Analyzer::Registry::non_analyzer_log_streams += { NetControl::DROP_LOG};
redef Analyzer::Registry::non_analyzer_log_streams += { NetControl::LOG };
redef Analyzer::Registry::non_analyzer_log_streams += { NetControl::SHUNT };
redef Analyzer::Registry::non_analyzer_log_streams += { Notice::ALARM_LOG };
redef Analyzer::Registry::non_analyzer_log_streams += { Notice::LOG };
redef Analyzer::Registry::non_analyzer_log_streams += { OpenFlow::LOG };
redef Analyzer::Registry::non_analyzer_log_streams += { PacketFilter::LOG };
redef Analyzer::Registry::non_analyzer_log_streams += { Reporter::LOG };
redef Analyzer::Registry::non_analyzer_log_streams += { Signatures::LOG };
redef Analyzer::Registry::non_analyzer_log_streams += { Software::LOG };
redef Analyzer::Registry::non_analyzer_log_streams += { Weird::LOG };

# Derived / interesting / influenced by analyzers
redef Analyzer::Registry::non_analyzer_log_streams += { Files::LOG };
redef Analyzer::Registry::non_analyzer_log_streams += { Intel::LOG };
redef Analyzer::Registry::non_analyzer_log_streams += { Traceroute::LOG };
redef Analyzer::Registry::non_analyzer_log_streams += { Tunnel::LOG };

# It's difficult... maybe IP/TCP/UDP analyzers. But extended/impacted by
# many others.
redef Analyzer::Registry::non_analyzer_log_streams += { Conn::LOG };



# There are also analyzers for which we don't provide logs
# ANALYZER_POP3
# ANALYZER_IMAP
# ANALYZER_FINGER
# ANALYZER_XMPP
# ANALYZER_GNUTELLA
# Files::ANALYZER_RSH
# ANALYZER_NFS

# Then there are some "support" analyzers
#
# Files::ANALYZER_ENTROPY
# Files::ANALYZER_DATA_EVENT
# Files::ANALYZER_MD5
# Files::ANALYZER_SHA1
# Files::ANALYZER_SHA256
# Files::ANALYZER_CONNSIZE
#
# There's also a number of "CONTENTS_" analyzers (?) that I don't know
# what they mean yet CONTENTS_NFS, CONTENTS_RLOGIN, CONTENTS_NCP, CONTENTS_RSH.

#
# I guess we can ignore them, or explicitly annotate with non-analyzer
# logs?
event zeek_init()
	{
	# This is showing some ideas. Each analyzer would to it local
	# to its own scripts.
	Analyzer::Registry::register_log(Analyzer::ANALYZER_SYSLOG, Syslog::LOG);

	Analyzer::Registry::register_log(Analyzer::ANALYZER_HTTP, HTTP::LOG,
	                                 [$event_groups=set("http-logging")]);

	Analyzer::Registry::register_log(Analyzer::ANALYZER_DNS, DNS::LOG,
	                                 [$event_groups=set("dns-logging")]);


	Analyzer::Registry::register_log(Analyzer::ANALYZER_FTP, FTP::LOG);
	Analyzer::Registry::register_relationship(Analyzer::ANALYZER_FTP,
	                                          Analyzer::ANALYZER_FTP_DATA);
	Analyzer::Registry::register_relationship(Analyzer::ANALYZER_FTP,
	                                          Analyzer::ANALYZER_FTP_ADAT);

	Analyzer::Registry::register_log(Analyzer::ANALYZER_IRC, IRC::LOG,
	                                 [$event_groups=set("irc-logging")]);
	Analyzer::Registry::register_relationship(Analyzer::ANALYZER_IRC,
	                                          Analyzer::ANALYZER_IRC_DATA);

	Analyzer::Registry::register_log(Analyzer::ANALYZER_SSL, SSL::LOG);
	Analyzer::Registry::register_relationship(Analyzer::ANALYZER_SSL,
	                                          Analyzer::ANALYZER_DTLS);

	Analyzer::Registry::register_log(Analyzer::ANALYZER_DCE_RPC, DCE_RPC::LOG);
	Analyzer::Registry::register_log(Analyzer::ANALYZER_DHCP, DHCP::LOG);
	Analyzer::Registry::register_log(Analyzer::ANALYZER_DNP3_TCP, DNP3::LOG);
	Analyzer::Registry::register_log(Analyzer::ANALYZER_DNP3_UDP, DNP3::LOG);
	Analyzer::Registry::register_log(Analyzer::ANALYZER_KRB, KRB::LOG);
	Analyzer::Registry::register_log(Analyzer::ANALYZER_MODBUS, Modbus::LOG);
	Analyzer::Registry::register_log(Analyzer::ANALYZER_MQTT, MQTT::CONNECT_LOG);
	Analyzer::Registry::register_log(Analyzer::ANALYZER_MQTT, MQTT::PUBLISH_LOG);
	Analyzer::Registry::register_log(Analyzer::ANALYZER_MQTT, MQTT::SUBSCRIBE_LOG);
	Analyzer::Registry::register_log(Analyzer::ANALYZER_MYSQL, mysql::LOG);
	Analyzer::Registry::register_log(Analyzer::ANALYZER_NTLM, NTLM::LOG);
	Analyzer::Registry::register_log(Analyzer::ANALYZER_NTP, NTP::LOG);
	Analyzer::Registry::register_log(Analyzer::ANALYZER_RADIUS, RADIUS::LOG);
	Analyzer::Registry::register_log(Analyzer::ANALYZER_RDP, RDP::LOG);
	Analyzer::Registry::register_log(Analyzer::ANALYZER_RDPEUDP, RDP::LOG);
	Analyzer::Registry::register_log(Analyzer::ANALYZER_RFB, RFB::LOG);
	Analyzer::Registry::register_log(Analyzer::ANALYZER_SIP, SIP::LOG);
	Analyzer::Registry::register_log(Analyzer::ANALYZER_SMB, SMB::FILES_LOG);
	Analyzer::Registry::register_log(Analyzer::ANALYZER_SMB, SMB::MAPPING_LOG);
	Analyzer::Registry::register_log(Analyzer::ANALYZER_SMTP, SMTP::LOG);
	Analyzer::Registry::register_log(Analyzer::ANALYZER_SNMP, SNMP::LOG);
	Analyzer::Registry::register_log(Analyzer::ANALYZER_SOCKS, SOCKS::LOG);
	Analyzer::Registry::register_log(Analyzer::ANALYZER_SSH, SSH::LOG);
	Analyzer::Registry::register_log(Files::ANALYZER_OCSP_REPLY, OCSP::LOG);
	Analyzer::Registry::register_log(Files::ANALYZER_PE, PE::LOG);
	Analyzer::Registry::register_log(Files::ANALYZER_X509, X509::LOG);
	}

event zeek_init() &priority=-100
	{
	# Demo
	Analyzer::disable_analyzer(Analyzer::ANALYZER_IRC);
	Analyzer::disable_analyzer(Analyzer::ANALYZER_IRC_DATA);
	Analyzer::disable_analyzer(Analyzer::ANALYZER_FTP);
	}

# Print all registered analyzers.
event zeek_done()
	{
	print "DONE", |Analyzer::Registry::enumerate()|;
	# for ( _, ai in Analyzer::Registry::enumerate() )
	#	print to_json(ai);
		# print cat(ai);
	}
