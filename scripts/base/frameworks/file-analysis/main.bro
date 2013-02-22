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

	type ActionArgs: record {
		extract_filename: string &optional;
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

		## Actions that have been added to the analysis of this file.
		actions: vector of Action &default=vector();

		## The corresponding arguments supplied to each element of *actions*.
		action_args: vector of ActionArgs &default=vector();

		## Some actions may directly yield results in this record.
		action_results: ActionResults;
	} &redef;

	## TODO: document
	global policy: hook(trig: Trigger, info: Info);

	# TODO: wrapper functions for BiFs ?
}
