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
	# TODO: what's a reasonable default?
	const default_bof_buffer_size: count = 256 &redef;

	## The default amount of time file analysis will wait for new file data
	## before giving up.
	## TODO: what's a reasonable default?
	#const default_timeout_interval: interval = 2 mins &redef;
	const default_timeout_interval: interval = 10 sec &redef;

	## The default amount of data that a user is allowed to extract
	## from a file to an event with the
	## :bro:see:`FileAnalysis::ACTION_DATA_EVENT` action.
	## TODO: what's a reasonable default?
	const default_data_event_len: count = 1024*1024 &redef;

	## Contains all metadata related to the analysis of a given file, some
	## of which is logged.
	type Info: record {
		## Unique identifier associated with a single file.
		file_id: string &log;
		## Unique identifier associated with the file if it was extracted
		## from a container file as part of the analysis.
		parent_file_id: string &log &optional;

		## The network protocol over which the file was transferred.
		protocol: string &log &optional;

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

		## The number of not all-in-sequence bytes over the course of the
		## analysis that had to be discarded due to a reassembly buffer size
		## of *reassembly_buffer_size* being filled.
		undelivered: count &default=0;

		## The amount of time between receiving new data for this file that
		## the analysis engine will wait before giving up on it.
		timeout_interval: interval &default=default_timeout_interval;

	} &redef;

	## TODO: document
	global policy: hook(trig: Trigger, info: Info);

	## TODO: document
	global postpone_timeout: function(file_id: string): bool;
}

function postpone_timeout(file_id: string): bool
	{
	return __postpone_timeout(file_id);
	}
