module Log;

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
		pred: function(rec: any): bool &optional;
		
		# A path for outputting everything matching this
		# filter. The path is either a string, or a function
		# called with a single ``ID`` argument and returning a string.
		#
		# The specific interpretation of the string is left to the
		# Writer, but if it's refering to a file, it's assumed that no
		# extension is given; the writer will add whatever is
		# appropiate.
		path: string &optional;
		dynamic_path: function(id: string): string &optional;
		
		# A subset of column names to record. If not given, all
		# columns are recorded.
		#select: set[string] &optional;
		
		# An event that is raised whenever the filter is applied
		# to an entry. The event receives the same parameter
		# as the predicate. It will always be generated,
		# independent of what the predicate returns.
		#ev: event(rec: any) &optional;
		
		# The writer to use.
		writer: Writer &default=default_writer;
		
		# Internal tracking of header names and order for this filter.
		#columns: string_vec &optional;
		};
	
	# Logs the record "rec" to the stream "id". The type of
	# "rec" must match the stream's "columns" field.
	global write: function(id: string, rec: any);
	#global log_ev: event(id: string, rec: any);
	
	# Returns an existing filter previously installed for stream
	# "id" under the given "name". If no such filter exists,
	# the record "NoSuchFilter" is returned.
	global get_filter: function(id: string, name: string) : Filter;
	
	
	global create_stream: function(id: string, log_record_type: string);
	global add_filter: function(id: string, filter: Filter);
	global remove_filter: function(id: string, filter: string): bool;
	
	global add_default_filter: function(id: string);
	global remove_default_filter: function(id: string): bool;
	
	global open_log_files: function(id: string);
	
	# This is the internal filter store.  The outer table is indexed with a string
	# representing the stream name that the set of Logging::Filters is applied to.
	global filters: table[string] of set[Filter];
	
	# This is the internal stream store.  The table is indexed by the stream name.
	global streams: table[string] of Stream;
	
	global files: table[string] of file;
}


# Sentinel representing an unknown filter.d
const NoSuchFilter: Filter = [$name="<unknown filter>", $path="unknown"];

function create_stream(id: string, log_record_type: string)
	{
	if ( id in streams )
		print fmt("Stream %s already exists!", id);
	
	streams[id] = [$name=log_record_type, $columns=record_type_to_vector(log_record_type)];
	# Insert this as a separate step because the file_opened event needs
	# the stream id to already exist.
	#streams[id]$_file = open_log_file(id);
	}
	
function add_filter(id: string, filter: Filter)
	{
	if ( id !in filters )
		filters[id] = set();
	
	add filters[id][filter];
	}
	
function remove_filter(id: string, filter: string): bool
	{
	for ( filt in filters[id] )
		{
		if ( filt$name == "default" )
			{
			delete filters[id][filt];
			return T;
			}
		}
	return F;
	}
	
function add_default_filter(id: string)
	{
	add_filter(id, [$name="default", $path=id]);
	}
	
function remove_default_filter(id: string): bool
	{
	return remove_filter("ssh", "default");
	}

event file_opened(f: file) &priority=10
	{
	# Only do any of this for files opened locally.
	if ( is_remote_event() ) return;

	# TODO: this shouldn't rely on .log being the extension
	local filename = gsub(get_file_name(f), /\.log$/, "");
	if ( filename in streams )
		{
		enable_raw_output(f);
		
		if (peer_description == "" ||
		    peer_description == "manager" ||
		    peer_description == "standalone")
			{
			print f, join_string_vec(streams[filename]$columns, "\t");
			}
		}
	else 
		{
		print "no raw output", filename;
		}
	}
	
function write(id: string, rec: any)
	{
	logging_log(id, rec);
	}


event bro_init() &priority=-10
	{
	# TODO: Check for logging streams without filters.
	}