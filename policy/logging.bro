module Log;

# Log::ID and Log::Writer are defined in bro.init due to circular dependencies.

export {
    # A stream defining the logging.
	type Stream: record {
	    # A record type defining the log's columns.
		columns: any;

	    # A optional event raised for each log entry. It must receive
		# a single argument of type $columns.
		ev: any &optional;
	};

	# A filter customizes logging.
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
		path_func: function(id: ID, path: string): string &optional;

		# A subset of column names to record. If not given, all
		# columns are recorded.
		include: set[string] &optional;
		exclude: set[string] &optional;

		# The writer to use.
		writer: Writer &optional;
    };

	global create_stream: function(id: Log::ID, stream: Log::Stream) : bool;
	global add_filter: function(id: Log::ID, filter: Log::Filter) : bool;
	global remove_filter: function(id: Log::ID, name: string) : bool;
	global write: function(id: Log::ID, columns: any) : bool;
	global set_buf: function(id: Log::ID, buffered: bool): bool;
	global flush: function(id: Log::ID): bool;
	global add_default_filter: function(id: ID) : bool;
	global remove_default_filter: function(id: ID) : bool;
}

@load logging.bif # Needs Log::Filter and Log::Stream defined.

module Log;

export {
	# The default writer to use if a filter does not specify
	# anything else.
	const default_writer = Log::WRITER_ASCII &redef;
}

function create_stream(id: Log::ID, stream: Log::Stream) : bool
	{
	if ( ! Log::__create_stream(id, stream) )
		return F;

	return add_default_filter(id);
	}
						   
function add_filter(id: Log::ID, filter: Log::Filter) : bool
	{
	return Log::__add_filter(id, filter);
	}

function remove_filter(id: Log::ID, name: string) : bool
	{
	return Log::__remove_filter(id, name);
	}

function write(id: Log::ID, columns: any) : bool
	{
	return Log::__write(id, columns);
	}

function set_buf(id: Log::ID, buffered: bool): bool
	{
	return Log::__set_buf(id, buffered);
	}

function flush(id: Log::ID): bool
	{
	return Log::__flush(id);
	}

function add_default_filter(id: ID) : bool
	{
	return add_filter(id, [$name="default"]);
	}

function remove_default_filter(id: ID) : bool
	{
	return remove_filter(id, "default");
	}

