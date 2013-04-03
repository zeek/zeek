##! An interface for driving the analysis of files, possibly independent of
##! any network protocol over which they're transported.

@load base/file_analysis.bif
@load base/frameworks/logging

module FileAnalysis;

export {
	redef enum Log::ID += {
		## Logging stream for file analysis.
		LOG
	};

	## The default buffer size used for storing the beginning of files.
	const default_bof_buffer_size: count = 1024 &redef;

	## The default amount of time file analysis will wait for new file data
	## before giving up.
	const default_timeout_interval: interval = 2 mins &redef;

	## A structure which represents a desired file analysis action to take.
	type ActionArgs: record {
		## The type of action.
		act: Action;
		## The local filename to which to write an extracted file.  Must be
		## set when *act* is :bro:see:`FileAnalysis::ACTION_EXTRACT`.
		extract_filename: string &optional;
	};

	## A structure which contains the results of certain file analysis actions.
	type ActionResults: record {
		## An MD5 digest of the file contents.
		md5: string &optional;
		## An SHA1 digest of the file contents.
		sha1: string &optional;
		## An SHA256 digest of the file contents.
		sha256: string &optional;
	};

	## Contains all metadata related to the analysis of a given file.
	type Info: record {
		## An identifier associated with a single file.
		file_id: string &log;

		## Identifier associated with a container file from which this one was
		## extracted as part of the file analysis.
		parent_file_id: string &log &optional;

		## An identification of the source of the file data.  E.g. it may be
		## a network protocol over which it was transferred, or a local file
		## path which was read, or some other input source.
		source: string &log &optional;

		## The set of connections over which the file was transferred.
		conns: table[conn_id] of connection &optional;

		## The time at which the last activity for the file was seen.
		last_active: time &log;

		## Number of bytes provided to the file analysis engine for the file.
		seen_bytes: count &log &default=0;

		## Total number of bytes that are supposed to comprise the full file.
		total_bytes: count &log &optional;

		## The number of bytes in the file stream that were completely missed
		## during the process of analysis e.g. due to dropped packets.
		missing_bytes: count &log &default=0;

		## The number of not all-in-sequence bytes in the file stream that
		## were delivered to file actions/analyzers due to reassembly buffer
		## overflow.
		overflow_bytes: count &log &default=0;

		## The amount of time between receiving new data for this file that
		## the analysis engine will wait before giving up on it.
		timeout_interval: interval &log &default=default_timeout_interval;

		## The number of bytes at the beginning of a file to save for later
		## inspection in *bof_buffer* field.
		bof_buffer_size: count &log &default=default_bof_buffer_size;

		## The content of the beginning of a file up to *bof_buffer_size* bytes.
		## This is also the buffer that's used for file/mime type detection.
		bof_buffer: string &optional;

		## A file type provided by libmagic against the *bof_buffer*, or
		## in the cases where no buffering of the beginning of file occurs,
		## an initial guess of the file type based on the first data seen.
		file_type: string &log &optional;

		## A mime type provided by libmagic against the *bof_buffer*, or
		## in the cases where no buffering of the beginning of file occurs,
		## an initial guess of the mime type based on the first data seen.
		mime_type: string &log &optional;

		## Actions that have been added to the analysis of this file.
		## Only meant for inspection by user scripts, not direct modification.
		actions: table[ActionArgs] of ActionResults;
	} &redef;

	## Fields that are derived from existing ones, and are set just in time
	## for logging purposes.
	redef record FileAnalysis::Info += {
		## Whether the file analysis timed out at least once for the file.
		timedout: bool &log &default=F;

		## Connection UIDS over which the file was transferred.
		conn_uids: set[string] &log &optional;

		## A set of action types taken during the file analysis.
		actions_taken: set[Action] &log &optional;

		## Local filenames of file extraction actions.
		extracted_files: set[string] &log &optional;

		## An MD5 digest of the file contents.
		md5: string &log &optional;

		## A SHA1 digest of the file contents.
		sha1: string &log &optional;

		## A SHA256 digest of the file contents.
		sha256: string &log &optional;
	};

	## Redefined here just so the *info* parameters of the events have the
	## right type information.
	redef record ActionArgs += {
		## An event which will be generated for all new file contents,
		## chunk-wise.
		chunk_event: event(info: Info, data: string, off: count) &optional;

		## An event which will be generated for all new file contents,
		## stream-wise.
		stream_event: event(info: Info, data: string) &optional;
	};

	## Evaluated every time a significant event occurs during the course of
	## file analysis.  Fields of the *info* argument may be modified or
	## other actions may be added or removed inside the body of any handlers
	## of this hook.
	global policy: hook(trig: Trigger, info: Info);

	## A table that can be used to disable file analysis completely for
	## any files transferred over given network protocol analyzers.
	const disable: table[AnalyzerTag] of bool = table() &redef;

	## Event that can be handled to access the Info record as it is sent on
	## to the logging framework.
	global log_file_analysis: event(rec: Info);

	## The salt concatenated to unique file handle strings generated by
	## :bro:see:`get_file_handle` before hashing them in to a file id
	## (the *file_id* field of :bro:see:`FileAnalysis::Info`).
	## Provided to help mitigate the possiblility of manipulating parts of
	## network connections that factor in to the file handle in order to
	## generate two handles that would hash to the same file id.
	const salt = "I recommend changing this." &redef;

	## Postpones the timeout of file analysis for a given file.
	## When used within a :bro:see:`FileAnalysis::policy` handler for
	## :bro:see:`FileAnalysis::TRIGGER_TIMEOUT`, the analysis will delay
	## timing out for the period of time indicated by the *timeout_interval*
	## field of :bro:see:`FileAnalysis::Info`.
	##
	## file_id: the file identifier string from the *file_id* field of
	##          :bro:see:`FileAnalysis::Info`.
	##
	## Returns: true if the timeout will be postponed, or false if analysis
	##          for the *file_id* isn't currently active.
	global postpone_timeout: function(file_id: string): bool;

	## Adds an action to the analysis of a given file.
	##
	## file_id: the file identifier string from the *file_id* field of
	##          :bro:see:`FileAnalysis::Info`.
	##
	## args: the action type to add along with any arguments it takes.
	##
	## Returns: true if the action will be added, or false if analysis
	##          for the *file_id* isn't currently active or the *args*
	##          were invalid for the action type.
	global add_action: function(file_id: string, args: ActionArgs): bool;

	## Removes an action from the analysis of a given file.
	##
	## file_id: the file identifier string from the *file_id* field of
	##          :bro:see:`FileAnalysis::Info`.
	##
	## args: the action (type and args) to remove.
	##
	## Returns: true if the action will be removed, or false if analysis
	##          for the *file_id* isn't currently active.
	global remove_action: function(file_id: string, args: ActionArgs): bool;

	## Stops/ignores any further analysis of a given file.
	##
	## file_id: the file identifier string from the *file_id* field of
	##          :bro:see:`FileAnalysis::Info`.
	##
	## Returns: true if analysis for the given file will be ignored for the
	##          rest of it's contents, or false if analysis for the *file_id*
	##          isn't currently active.
	global stop: function(file_id: string): bool;

	## Sends a sequential stream of data in for file analysis.
	## Meant for use when providing external file analysis input (e.g.
	## from the input framework).
	##
	## source: a string that uniquely identifies the logical file that the
	##         data is a part of and describes its source.
	##
	## data: bytestring contents of the file to analyze.
	global data_stream: function(source: string, data: string);

	## Sends a non-sequential chunk of data in for file analysis.
	## Meant for use when providing external file analysis input (e.g.
	## from the input framework).
	##
	## source: a string that uniquely identifies the logical file that the
	##         data is a part of and describes its source.
	##
	## data: bytestring contents of the file to analyze.
	##
	## offset: the offset within the file that this chunk starts.
	global data_chunk: function(source: string, data: string, offset: count);

	## Signals a content gap in the file bytestream.
	## Meant for use when providing external file analysis input (e.g.
	## from the input framework).
	##
	## source: a string that uniquely identifies the logical file that the
	##         data is a part of and describes its source.
	##
	## offset: the offset within the file that this gap starts.
	##
	## len: the number of bytes that are missing.
	global gap: function(source: string, offset: count, len: count);

	## Signals the total size of a file.
	## Meant for use when providing external file analysis input (e.g.
	## from the input framework).
	##
	## source: a string that uniquely identifies the logical file that the
	##         data is a part of and describes its source.
	##
	## size: the number of bytes that comprise the full file.
	global set_size: function(source: string, size: count);

	## Signals the end of a file.
	## Meant for use when providing external file analysis input (e.g.
	## from the input framework).
	##
	## source: a string that uniquely identifies the logical file that the
	##         data is a part of and describes its source.
	global eof: function(source: string);
}

function postpone_timeout(file_id: string): bool
	{
	return __postpone_timeout(file_id);
	}

function add_action(file_id: string, args: ActionArgs): bool
	{
	return __add_action(file_id, args);
	}

function remove_action(file_id: string, args: ActionArgs): bool
	{
	return __remove_action(file_id, args);
	}

function stop(file_id: string): bool
	{
	return __stop(file_id);
	}

function data_stream(source: string, data: string)
	{
	__data_stream(source, data);
	}

function data_chunk(source: string, data: string, offset: count)
	{
	__data_chunk(source, data, offset);
	}

function gap(source: string, offset: count, len: count)
	{
	__gap(source, offset, len);
	}

function set_size(source: string, size: count)
	{
	__set_size(source, size);
	}

function eof(source: string)
	{
	__eof(source);
	}

event bro_init() &priority=5
	{
	Log::create_stream(FileAnalysis::LOG,
	                   [$columns=Info, $ev=log_file_analysis]);
	}

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	&priority=5
	{
	if ( trig != FileAnalysis::TRIGGER_TIMEOUT ) return;
	info$timedout = T;
	}

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	&priority=-5
	{
	if ( trig != FileAnalysis::TRIGGER_EOF &&
	     trig != FileAnalysis::TRIGGER_DONE ) return;

	info$conn_uids = set();
	if ( info?$conns )
		for ( cid in info$conns )
			add info$conn_uids[info$conns[cid]$uid];

	info$actions_taken = set();
	info$extracted_files = set();

	for ( act in info$actions )
		{
		add info$actions_taken[act$act];
		local result: FileAnalysis::ActionResults = info$actions[act];

		switch ( act$act ) {
		case FileAnalysis::ACTION_EXTRACT:
			add info$extracted_files[act$extract_filename];
			break;
		case FileAnalysis::ACTION_MD5:
			if ( result?$md5 )
				info$md5 = result$md5;
			break;
		case FileAnalysis::ACTION_SHA1:
			if ( result?$sha1 )
				info$sha1 = result$sha1;
			break;
		case FileAnalysis::ACTION_SHA256:
			if ( result?$sha256 )
				info$sha256 = result$sha256;
			break;
		case FileAnalysis::ACTION_DATA_EVENT:
			# no direct result
			break;
		}
		}

	Log::write(FileAnalysis::LOG, info);
	}
