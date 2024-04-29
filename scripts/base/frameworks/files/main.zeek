##! An interface for driving the analysis of files, possibly independent of
##! any network protocol over which they're transported.

@load base/bif/file_analysis.bif
@load base/frameworks/analyzer
@load base/frameworks/logging
@load base/utils/site

module Files;

export {
	redef enum Log::ID += {
		## Logging stream for file analysis.
		LOG
	};

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## A structure which parameterizes a type of file analysis.
	type AnalyzerArgs: record {
		## An event which will be generated for all new file contents,
		## chunk-wise.  Used when *tag* (in the
		## :zeek:see:`Files::add_analyzer` function) is
		## :zeek:see:`Files::ANALYZER_DATA_EVENT`.
		chunk_event: event(f: fa_file, data: string, off: count) &optional;

		## An event which will be generated for all new file contents,
		## stream-wise.  Used when *tag* is
		## :zeek:see:`Files::ANALYZER_DATA_EVENT`.
		stream_event: event(f: fa_file, data: string) &optional;
	} &redef;

	## Contains all metadata related to the analysis of a given file.
	## For the most part, fields here are derived from ones of the same name
	## in :zeek:see:`fa_file`.
	type Info: record {
		## The time when the file was first seen.
		ts: time &log;

		## An identifier associated with a single file.
		fuid: string &log;

		## If this file, or parts of it, were transferred over a
		## network connection, this is the uid for the connection.
		uid: string &log &optional;

		## If this file, or parts of it, were transferred over a
		## network connection, this shows the connection.
		id: conn_id &log &optional;

		## An identification of the source of the file data.  E.g. it
		## may be a network protocol over which it was transferred, or a
		## local file path which was read, or some other input source.
		source: string &log &optional;

		## A value to represent the depth of this file in relation
		## to its source.  In SMTP, it is the depth of the MIME
		## attachment on the message.  In HTTP, it is the depth of the
		## request within the TCP connection.
		depth: count &default=0 &log;

		## A set of analysis types done during the file analysis.
		analyzers: set[string] &default=string_set() &log;

		## A mime type provided by the strongest file magic signature
		## match against the *bof_buffer* field of :zeek:see:`fa_file`,
		## or in the cases where no buffering of the beginning of file
		## occurs, an initial guess of the mime type based on the first
		## data seen.
		mime_type: string &log &optional;

		## A filename for the file if one is available from the source
		## for the file.  These will frequently come from
		## "Content-Disposition" headers in network protocols.
		filename: string &log &optional;

		## The duration the file was analyzed for.
		duration: interval &log &default=0secs;

		## If the source of this file is a network connection, this field
		## indicates if the data originated from the local network or not as
		## determined by the configured :zeek:see:`Site::local_nets`.
		local_orig: bool &log &optional;

		## If the source of this file is a network connection, this field
		## indicates if the file is being sent by the originator of the
		## connection or the responder.
		is_orig: bool &log &optional;

		## Number of bytes provided to the file analysis engine for the file.
		## The value refers to the total number of bytes processed for this
		## file across all connections seen by the current Zeek instance.
		seen_bytes: count &log &default=0;

		## Total number of bytes that are supposed to comprise the full file.
		total_bytes: count &log &optional;

		## The number of bytes in the file stream that were completely missed
		## during the process of analysis e.g. due to dropped packets.
		## The value refers to number of bytes missed for this file
		## across all connections seen by the current Zeek instance.
		missing_bytes: count &log &default=0;

		## The number of bytes in the file stream that were not delivered to
		## stream file analyzers.  This could be overlapping bytes or
		## bytes that couldn't be reassembled.
		overflow_bytes: count &log &default=0;

		## Whether the file analysis timed out at least once for the file.
		timedout: bool &log &default=F;

		## Identifier associated with a container file from which this one was
		## extracted as part of the file analysis.
		parent_fuid: string &log &optional;
	} &redef;

	## A table that can be used to disable file analysis completely for
	## any files transferred over given network protocol analyzers.
	const disable: table[Files::Tag] of bool = table() &redef;

	## Decide if you want to automatically attached analyzers to
	## files based on the detected mime type of the file.
	const analyze_by_mime_type_automatically = T &redef;

	## The default setting for file reassembly.
	option enable_reassembler = T;

	## The default per-file reassembly buffer size.
	const reassembly_buffer_size = 524288 &redef;

	## Lookup to see if a particular file id exists and is still valid.
	##
	## fuid: the file id.
	##
	## Returns: T if the file uid is known.
	global file_exists: function(fuid: string): bool;

	## Lookup an :zeek:see:`fa_file` record with the file id.
	##
	## fuid: the file id.
	##
	## Returns: the associated :zeek:see:`fa_file` record.
	global lookup_file: function(fuid: string): fa_file;

	## Allows the file reassembler to be used if it's necessary because the
	## file is transferred out of order.
	##
	## f: the file.
	global enable_reassembly: function(f: fa_file);

	## Disables the file reassembler on this file.  If the file is not
	## transferred out of order this will have no effect.
	##
	## f: the file.
	global disable_reassembly: function(f: fa_file);

	## Set the maximum size the reassembly buffer is allowed to grow
	## for the given file.
	##
	## f: the file.
	##
	## max: Maximum allowed size of the reassembly buffer.
	global set_reassembly_buffer_size: function(f: fa_file, max: count);

	## Sets the *timeout_interval* field of :zeek:see:`fa_file`, which is
	## used to determine the length of inactivity that is allowed for a file
	## before internal state related to it is cleaned up.  When used within
	## a :zeek:see:`file_timeout` handler, the analysis will delay timing out
	## again for the period specified by *t*.
	##
	## f: the file.
	##
	## t: the amount of time the file can remain inactive before discarding.
	##
	## Returns: true if the timeout interval was set, or false if analysis
	##          for the file isn't currently active.
	global set_timeout_interval: function(f: fa_file, t: interval): bool;

	## Enables a file analyzer.
	##
	## tag: the analyzer type to enable.
	##
	## Returns: false if the analyzer tag could not be found, else true.
	global enable_analyzer: function(tag: Files::Tag): bool;

	## Disables a file analyzer.
	##
	## tag: the analyzer type to disable.
	##
	## Returns: false if the analyzer tag could not be found, else true.
	global disable_analyzer: function(tag: Files::Tag): bool;

	## Checks whether a file analyzer is generally enabled.
	##
	## tag: the analyzer type to check.
	##
	## Returns: true if the analyzer is generally enabled, else false.
	global analyzer_enabled: function(tag: Files::Tag): bool;

	## Adds an analyzer to the analysis of a given file.
	##
	## f: the file.
	##
	## tag: the analyzer type.
	##
	## args: any parameters the analyzer takes.
	##
	## Returns: true if the analyzer will be added, or false if analysis
	##          for the file isn't currently active or the *args*
	##          were invalid for the analyzer type.
	global add_analyzer: function(f: fa_file,
	                              tag: Files::Tag,
	                              args: AnalyzerArgs &default=AnalyzerArgs()): bool;

	## Removes an analyzer from the analysis of a given file.
	##
	## f: the file.
	##
	## tag: the analyzer type.
	##
	## args: the analyzer (type and args) to remove.
	##
	## Returns: true if the analyzer will be removed, or false if analysis
	##          for the file isn't currently active.
	global remove_analyzer: function(f: fa_file,
	                                 tag: Files::Tag,
	                                 args: AnalyzerArgs &default=AnalyzerArgs()): bool;

	## Stops/ignores any further analysis of a given file.
	##
	## f: the file.
	##
	## Returns: true if analysis for the given file will be ignored for the
	##          rest of its contents, or false if analysis for the file
	##          isn't currently active.
	global stop: function(f: fa_file): bool;

	## Translates a file analyzer enum value to a string with the
	## analyzer's name.
	##
	## tag: The analyzer tag.
	##
	## Returns: The analyzer name corresponding to the tag.
	global analyzer_name: function(tag: Files::Tag): string;

	## Provides a text description regarding metadata of the file.
	## For example, with HTTP it would return a URL.
	##
	## f: The file to be described.
	##
	## Returns: a text description regarding metadata of the file.
	global describe: function(f: fa_file): string;

	type ProtoRegistration: record {
		## A callback to generate a file handle on demand when
		## one is needed by the core.
		get_file_handle: function(c: connection, is_orig: bool): string;

		## A callback to "describe" a file.  In the case of an HTTP
		## transfer the most obvious description would be the URL.
		## It's like an extremely compressed version of the normal log.
		describe: function(f: fa_file): string
				&default=function(f: fa_file): string { return ""; };
	};

	## Register callbacks for protocols that work with the Files framework.
	## The callbacks must uniquely identify a file and each protocol can
	## only have a single callback registered for it.
	##
	## tag: Tag for the protocol analyzer having a callback being registered.
	##
	## reg: A :zeek:see:`Files::ProtoRegistration` record.
	##
	## Returns: true if the protocol being registered was not previously registered.
	global register_protocol: function(tag: Analyzer::Tag, reg: ProtoRegistration): bool;

	## Register a callback for file analyzers to use if they need to do some
	## manipulation when they are being added to a file before the core code
	## takes over.  This is unlikely to be interesting for users and should
	## only be called by file analyzer authors but is *not required*.
	##
	## tag: Tag for the file analyzer.
	##
	## callback: Function to execute when the given file analyzer is being added.
	global register_analyzer_add_callback: function(tag: Files::Tag, callback: function(f: fa_file, args: AnalyzerArgs));

	## Registers a set of MIME types for an analyzer. If a future connection on one of
	## these types is seen, the analyzer will be automatically assigned to parsing it.
	## The function *adds* to all MIME types already registered, it doesn't replace
	## them.
	##
	## tag: The tag of the analyzer.
	##
	## mts: The set of MIME types, each in the form "foo/bar" (case-insensitive).
	##
	## Returns: True if the MIME types were successfully registered.
	global register_for_mime_types: function(tag: Files::Tag, mts: set[string]) : bool;

	## Registers a MIME type for an analyzer. If a future file with this type is seen,
	## the analyzer will be automatically assigned to parsing it. The function *adds*
	## to all MIME types already registered, it doesn't replace them.
	##
	## tag: The tag of the analyzer.
	##
	## mt: The MIME type in the form "foo/bar" (case-insensitive).
	##
	## Returns: True if the MIME type was successfully registered.
	global register_for_mime_type: function(tag: Files::Tag, mt: string) : bool;

	## Returns a set of all MIME types currently registered for a specific analyzer.
	##
	## tag: The tag of the analyzer.
	##
	## Returns: The set of MIME types.
	global registered_mime_types: function(tag: Files::Tag) : set[string];

	## Returns a table of all MIME-type-to-analyzer mappings currently registered.
	##
	## Returns: A table mapping each analyzer to the set of MIME types
	##          registered for it.
	global all_registered_mime_types: function() : table[Files::Tag] of set[string];

	## Event that can be handled to access the Info record as it is sent on
	## to the logging framework.
	global log_files: event(rec: Info);
}

redef record fa_file += {
	info: Info &optional;
};

# Store the callbacks for protocol analyzers that have files.
global registered_protocols: table[Analyzer::Tag] of ProtoRegistration = table();

# Store the MIME type to analyzer mappings.
global mime_types: table[Files::Tag] of set[string];
global mime_type_to_analyzers: table[string] of set[Files::Tag];

global analyzer_add_callbacks: table[Files::Tag] of function(f: fa_file, args: AnalyzerArgs) = table();

event zeek_init() &priority=5
	{
	Log::create_stream(Files::LOG, [$columns=Info, $ev=log_files, $path="files", $policy=log_policy]);
	}

function set_info(f: fa_file)
	{
	if ( ! f?$info )
		{
		local tmp: Info = Info($ts=f$last_active,
		                       $fuid=f$id);
		f$info = tmp;
		}

	if ( f?$parent_id )
		f$info$parent_fuid = f$parent_id;
	if ( f?$source )
		f$info$source = f$source;
	f$info$duration = f$last_active - f$info$ts;
	f$info$seen_bytes = f$seen_bytes;
	if ( f?$total_bytes )
		f$info$total_bytes = f$total_bytes;
	f$info$missing_bytes = f$missing_bytes;
	f$info$overflow_bytes = f$overflow_bytes;
	if ( f?$is_orig )
		f$info$is_orig = f$is_orig;
	}

function file_exists(fuid: string): bool
	{
	return __file_exists(fuid);
	}

function lookup_file(fuid: string): fa_file
	{
	return __lookup_file(fuid);
	}

function set_timeout_interval(f: fa_file, t: interval): bool
	{
	return __set_timeout_interval(f$id, t);
	}

function enable_reassembly(f: fa_file)
	{
	__enable_reassembly(f$id);
	}

function disable_reassembly(f: fa_file)
	{
	__disable_reassembly(f$id);
	}

function set_reassembly_buffer_size(f: fa_file, max: count)
	{
	__set_reassembly_buffer(f$id, max);
	}

function enable_analyzer(tag: Files::Tag): bool
	{
	return __enable_analyzer(tag);
	}

function disable_analyzer(tag: Files::Tag): bool
	{
	return __disable_analyzer(tag);
	}

function analyzer_enabled(tag: Files::Tag): bool
	{
	return __analyzer_enabled(tag);
	}

function add_analyzer(f: fa_file, tag: Files::Tag, args: AnalyzerArgs): bool
	{
	if ( ! Files::analyzer_enabled(tag) )
		return F;

	add f$info$analyzers[Files::analyzer_name(tag)];

	if ( tag in analyzer_add_callbacks )
		analyzer_add_callbacks[tag](f, args);

	if ( ! __add_analyzer(f$id, tag, args) )
		{
		Reporter::warning(fmt("Analyzer %s not added successfully to file %s.", tag, f$id));
		return F;
		}
	return T;
	}

function register_analyzer_add_callback(tag: Files::Tag, callback: function(f: fa_file, args: AnalyzerArgs))
	{
	analyzer_add_callbacks[tag] = callback;
	}

function remove_analyzer(f: fa_file, tag: Files::Tag, args: AnalyzerArgs): bool
	{
	return __remove_analyzer(f$id, tag, args);
	}

function stop(f: fa_file): bool
	{
	return __stop(f$id);
	}

function analyzer_name(tag: Files::Tag): string
	{
	return __analyzer_name(tag);
	}

function register_protocol(tag: Analyzer::Tag, reg: ProtoRegistration): bool
	{
	local result = (tag !in registered_protocols);
	registered_protocols[tag] = reg;
	return result;
	}

function register_for_mime_types(tag: Files::Tag, mime_types: set[string]) : bool
	{
	local rc = T;

	for ( mt in mime_types )
		{
		if ( ! register_for_mime_type(tag, mt) )
			rc = F;
		}

	return rc;
	}

function register_for_mime_type(tag: Files::Tag, mt: string) : bool
	{
	if ( tag !in mime_types )
		{
		mime_types[tag] = set();
		}
	add mime_types[tag][mt];

	if ( mt !in mime_type_to_analyzers )
		{
		mime_type_to_analyzers[mt] = set();
		}
	add mime_type_to_analyzers[mt][tag];

	return T;
	}

function registered_mime_types(tag: Files::Tag) : set[string]
	{
	return tag in mime_types ? mime_types[tag] : set();
	}

function all_registered_mime_types(): table[Files::Tag] of set[string]
	{
	return mime_types;
	}

function describe(f: fa_file): string
	{
	if ( ! Analyzer::has_tag(f$source) )
		return "";

	local tag = Analyzer::get_tag(f$source);
	if ( tag !in registered_protocols )
		return "";

	local handler = registered_protocols[tag];
	return handler$describe(f);
	}

# Only warn once about un-registered get_file_handle()
global missing_get_file_handle_warned: table[Files::Tag] of bool &default=F;

event get_file_handle(tag: Files::Tag, c: connection, is_orig: bool) &priority=5
	{
	if ( tag !in registered_protocols )
		{
		if ( ! missing_get_file_handle_warned[tag] )
			{
			missing_get_file_handle_warned[tag] = T;
			Reporter::warning(fmt("get_file_handle() handler missing for %s", tag));
			}

		set_file_handle(fmt("%s-fallback-%s-%s-%s", tag, c$uid, is_orig, network_time()));
		return;
		}

	local handler = registered_protocols[tag];
	set_file_handle(handler$get_file_handle(c, is_orig));
	}

event file_new(f: fa_file) &priority=10
	{
	set_info(f);

	if ( enable_reassembler )
		{
		Files::enable_reassembly(f);
		Files::set_reassembly_buffer_size(f, reassembly_buffer_size);
		}
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=10
	{
	set_info(f);

	local cid = c$id;
	if( |Site::local_nets| > 0 )
		f$info$local_orig=Site::is_local_addr(f$is_orig ? cid$orig_h : cid$resp_h);
	}

event file_sniff(f: fa_file, meta: fa_metadata) &priority=10
	{
	set_info(f);

	if ( ! meta?$mime_type )
		return;

	f$info$mime_type = meta$mime_type;

	if ( analyze_by_mime_type_automatically &&
	     meta$mime_type in mime_type_to_analyzers )
		{
		local analyzers = mime_type_to_analyzers[meta$mime_type];
		for ( a in analyzers )
			Files::add_analyzer(f, a);
		}
	}

event file_timeout(f: fa_file) &priority=10
	{
	set_info(f);
	f$info$timedout = T;
	}

event file_state_remove(f: fa_file) &priority=10
	{
	set_info(f);
	}

event file_state_remove(f: fa_file) &priority=-10
	{
	# No network connection for this file? Just write it out once without
	# uid and c$id fields.
	if ( ! f?$conns || |f$conns| == 0 )
		{
		Log::write(Files::LOG, f$info);
		return;
		}

	# If f was seen over multiple connections, unroll them here as
	# multiple files.log entries. In previous versions of Zeek, there
	# would only be a single files.log entry (per worker) with multiple
	# tx_hosts, rx_hosts and conn_uids associated. This changed with v5.1
	# to have individual log entries that all share the same fuid value.
	for ( [cid], c in f$conns )
		{
		# Make a copy of the record when there's more than one
		# connection so that the log_files event doesn't see
		# the same record multiple times due to it being queued
		# by reference in Log::write() rather than by copy.
		local info = |f$conns| > 1 ? copy(f$info) : f$info;
		info$uid = c$uid;
		info$id = c$id;
		Log::write(Files::LOG, info);
		}
	}
