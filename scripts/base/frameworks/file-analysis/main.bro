##! TODO add some comments here

@load base/file_analysis.bif

# TODO: do logging here?
@load base/frameworks/logging

# dependendies for file handle determination
@load base/protocols/http/main
@load base/protocols/http/utils
@load base/protocols/ftp/main

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
	## TODO: what's a reasonable default?
	#const default_timeout_interval: interval = 2 mins &redef;
	const default_timeout_interval: interval = 10 sec &redef;

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

		## The set of connections over which the file was transferred,
		## indicated by UID strings.
		conn_uids: set[string] &log &optional;
		## The set of connections over which the file was transferred,
		## indicated by 5-tuples.
		conn_ids: set[conn_id] &optional;

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
		bof_buffer_size: count &default=default_bof_buffer_size;

		## The content of the beginning of a file up to *bof_buffer_size* bytes.
		## This is also the buffer that's used for file/mime type detection.
		bof_buffer: string &optional;

		## An initial guess at file type.
		file_type: string &optional;
		## An initial guess at mime type.
		mime_type: string &optional;

		## Actions that have been added to the analysis of this file.
		## Not meant to be modified directly by scripts.
		actions: table[ActionArgs] of ActionResults;
	} &redef;

	## TODO: document
	global policy: hook(trig: Trigger, info: Info);

	global get_handle: function(c: connection, is_orig: bool): string &redef;

	# TODO: wrapper functions for BiFs ?
}

function conn_str(c: connection): string
	{
	return fmt("%s:%s -> %s:%s", c$id$orig_h, c$id$orig_p,
	           c$id$resp_h, c$id$resp_p);
	}

function get_handle(c: connection, is_orig: bool): string
	{
	local rval: string = "";
	local cid: conn_id = c$id;

	if ( "ftp-data" in c$service )
		rval = fmt("%s ftp-data: %s", c$start_time, conn_str(c));

	if ( "irc-dcc-data" in c$service )
		rval = fmt("%s irc-dcc-data: %s", c$start_time, conn_str(c));

	else if ( c?$http )
		{
		if ( c$http$range_request )
			rval = fmt("%s http(%s): %s: %s", c$start_time, is_orig,
			           c$id$orig_h, HTTP::build_url(c$http));
		else
			rval = fmt("%s http(%s, %s): %s", c$start_time, is_orig,
			           c$http$trans_depth, conn_str(c));
		}

	#print fmt("file handle: %s", rval);
	return rval;
	}
