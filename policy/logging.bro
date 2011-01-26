module Logging;

export {
	# The set of writers Bro provides.
	type Writer: enum {
		WRITER_DEFAULT, # See default_writer below.
		WRITER_CSV,
		WRITER_DATA_SERIES,
		WRITER_SYSLOG
	};
	
	# Each stream gets a unique ID. This type will be extended by
	# other scripts.
	type ID: enum {
		Unknown
		};
	
	# The default writer to use if a filter does not specify
	# anything else.
	const default_writer = WRITER_CSV &redef;
	
	# Type defining a stream.
	type Stream: record {
		name:     string;
		columns:  string_vec;
		};
	
	# A filter defining what to record.
	type Filter: record {
		# A name to reference this filter.
		name: string;
    	
		# A predicate returning True if the filter wants a log entry
		# to be recorded. If not given, an implicit True is assumed
		# for all entries. The predicate receives one parameter:
		# an instance of the log's record type with the fields to be
		# logged.
		pred: function(log: any) &optional;
    	
		# A path for outputting everything matching this
		# filter. The path is either a string, or a function
		# called with a single ``ID`` argument and returning a string.
		#
		# The specific interpretation of the string is left to the
		# Writer, but if it's refering to a file, it's assumed that no
		# extension is given; the writer will add whatever is
		# appropiate.
		path: any &optional;
    	
		# A subset of column names to record. If not given, all
		# columns are recorded.
		select: set[string] &optional;
    	
		# An event that is raised whenever the filter is applied
		# to an entry. The event receives the same parameter
		# as the predicate. It will always be generated,
		# independent of what the predicate returns.
		ev: event(l: any) &optional;
    	
		# The writer to use.
		writer: Writer &default=default_writer;
		};
	
	
	global filters: table[string] of set[Filter];
	global streams: table[string] of Stream;
	
	# Logs the record "rec" to the stream "id". The type of
	# "rec" must match the stream's "columns" field.
	global log: function(id: string, rec: any);
	global log_ev: event(id: string, rec: any);
	
	# Returns an existing filter previously installed for stream
	# "id" under the given "name". If no such filter exists,
	# the record "NoSuchFilter" is returned.
	global get_filter: function(id: string, name: string) : Filter;
	
	global create_stream: function(id: string, log_record_type: string);
	global add_filter: function(id: string, filter: Filter);
	
	global open_log_files: function(id: string);
	
}

# Sentinel representing an unknown filter.
const NoSuchFilter: Filter = [$name="<unknown filter>"];

function create_stream(id: string, log_record_type: string)
	{
	if ( id in streams )
		print fmt("Stream %s already exists!", id);
	
	streams[id] = [$name=log_record_type, $columns=record_type_to_vector(log_record_type)];
	}
	
function add_filter(id: string, filter: Filter)
	{
	if ( id !in filters )
		filters[id] = set();
	
	# TODO: This is broken and waiting on a bug fix for &optional fields
	#       in records being used as indexes.
	#add filt[filter];
	}
	
function log(id: string, rec: any)
	{
	logging_log(id, rec);
	}

