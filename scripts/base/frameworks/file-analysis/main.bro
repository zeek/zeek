##! TODO add some comments here

@load base/file_analysis.bif

# TODO: do logging here?
@load base/frameworks/logging

module FileAnalysis;

export {
	redef enum Log::ID += {
		## Logging stream for file analysis.
		LOG
	};

	## The default buffer size used to reassemble files.
	# TODO: what's a reasonable default?
	const default_reassembly_buffer_size: count = 1024*1024 &redef;

	## The default buffer size used for storing the beginning of files.
	const default_bof_buffer_size: count = 1024 &redef;

	## The default amount of time file analysis will wait for new file data
	## before giving up.
	const default_timeout_interval: interval = 2 mins &redef;

	# Needed a forward declaration for event parameters...
	type Info: record {};

	type ActionArgs: record {
		act: Action;
		extract_filename: string &optional;
		chunk_event: event(info: Info, data: string, off: count) &optional;
		stream_event: event(info: Info, data: string) &optional;
	};

	type ActionResults: record {
		md5: string &optional;
		sha1: string &optional;
		sha256: string &optional;
	};

	## Contains all metadata related to the analysis of a given file, some
	## of which is logged.
	type Info: record {
		## Unique identifier associated with a single file.
		file_id: string &log;
		## Unique identifier associated with the file if it was extracted
		## from a container file as part of the analysis.
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
		## Total number of bytes that are supposed to comprise the file content.
		total_bytes: count &log &optional;

		## The number of bytes in the file stream that were completely missed
		## during the process of analysis e.g. due to dropped packets.
		## analysis that had to be discarded due to a reassembly buffer size
		## of *reassembly_buffer_size* being filled.
		missing_bytes: count &log &default=0;

		## The number of not all-in-sequence bytes in the file stream that
		## were delivered to file actions/analyzers due to reassembly buffer
		## size of *reassembly_buffer_size* being filled.
		overflow_bytes: count &log &default=0;

		## The amount of time between receiving new data for this file that
		## the analysis engine will wait before giving up on it.
		timeout_interval: interval &log &default=default_timeout_interval;

		## The number of bytes at the beginning of a file to save for later
		## inspection in *bof_buffer* field of
		## :bro:see:`FileAnalysis::ActionResults`.
		bof_buffer_size: count &log &default=default_bof_buffer_size;

		## The content of the beginning of a file up to *bof_buffer_size* bytes.
		## This is also the buffer that's used for file/mime type detection.
		bof_buffer: string &optional;

		## An initial guess at file type.
		file_type: string &log &optional;
		## An initial guess at mime type.
		mime_type: string &log &optional;

		## Actions that have been added to the analysis of this file.
		## Not meant to be modified directly by scripts.
		actions: table[ActionArgs] of ActionResults;
	} &redef;

	## TODO: document
	global policy: hook(trig: Trigger, info: Info);

	type HandleCallback: function(c: connection, is_orig: bool): string;

	const handle_callbacks: table[AnalyzerTag] of HandleCallback = {} &redef;

	global get_handle: function(c: connection, is_orig: bool): string &redef;

	# TODO: wrapper functions for BiFs ?

	## Event that can be handled to access the Info record as it is sent on
	## to the logging framework.
	global log_file_analysis: event(rec: Info);
}

event bro_init() &priority=5
	{
	Log::create_stream(FileAnalysis::LOG,
	                   [$columns=Info, $ev=log_file_analysis]);
	}

redef record FileAnalysis::Info += {
	conn_uids: set[string] &log &optional;
	actions_taken: set[Action] &log &optional;
	extracted_files: set[string] &log &optional;
	md5: string &log &optional;
	sha1: string &log &optional;
	sha256: string &log &optional;
};

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	&priority=-10
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
