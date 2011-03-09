module Log;

# Log::ID and Log::Writer are defined in bro.init due to circular dependencies.

export {
	# If true, local logging is by default enabled for all filters.
	const enable_local_logging = T &redef;

	# If true, remote logging is by default enabled for all filters.
	const enable_remote_logging = T &redef;

	# The default writer to use.
	const default_writer = Log::WRITER_ASCII &redef;

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

		# If true, record all log records locally.
		log_local: bool &default=enable_local_logging;

		# If true, pass all log records on to remote peers if they request it.
		log_remote: bool &default=enable_remote_logging;

		# The writer to use.
		writer: Writer &default=Log::default_writer;
    };

	### Log rotation support.

	# Information passed to a rotation callback function.
	type RotationInfo: record {
		writer: Writer;	# The writer.
		path: string;	# Original path value.
		open: time;	# Time when opened.
		close: time;	# Time when closed.
	};

	# Default rotation interval; zero disables rotation.
	const default_rotation_interval = 0secs &redef;

	# Default naming suffix format.
	const default_rotation_date_format = "%y-%m-%d_%H.%M.%S" &redef;

	# Default postprocessor for writers outputting into files.
	const default_rotation_postprocessor = "" &redef;

	# Default function to construct the name of the rotated file.
	# The default implementation includes
	# default_rotation_date_format into the file name.   
	global default_rotation_path_func: function(info: RotationInfo) : string &redef;

	type RotationControl: record  {
		interv: interval &default=default_rotation_interval;
		date_fmt: string &default=default_rotation_date_format;
		postprocessor: string &default=default_rotation_postprocessor;
	};

	# Defines rotation parameters per (id, path) tuple.
	const rotation_control: table[Writer, string] of Log::RotationControl &default=[] &redef;

	### Function.

	const no_filter: Filter = [$name="<not found>"]; # Sentinel.

	global create_stream: function(id: Log::ID, stream: Log::Stream) : bool;
	global add_filter: function(id: Log::ID, filter: Log::Filter) : bool;
	global remove_filter: function(id: Log::ID, name: string) : bool;
	global get_filter: function(id: Log::ID, name: string) : Filter; # Returns no_filter if not found.
	global write: function(id: Log::ID, columns: any) : bool;
	global set_buf: function(id: Log::ID, buffered: bool): bool;
	global flush: function(id: Log::ID): bool;
	global add_default_filter: function(id: ID) : bool;
	global remove_default_filter: function(id: ID) : bool;
}

# We keep a script-level copy of all filters so that we can directly manipulate them.
global filters: table[ID, string] of Filter;

@load logging.bif # Needs Log::Filter and Log::Stream defined.

module Log;

function default_rotation_path_func(info: RotationInfo) : string
	{
	local date_fmt = rotation_control[info$writer, info$path]$date_fmt;
	return fmt("%s-%s", info$path, strftime(date_fmt, info$open));
	}

function create_stream(id: Log::ID, stream: Log::Stream) : bool
	{
	if ( ! Log::__create_stream(id, stream) )
		return F;

	return add_default_filter(id);
	}
						   
function add_filter(id: Log::ID, filter: Log::Filter) : bool
	{
	filters[id, filter$name] = filter;
	return Log::__add_filter(id, filter);
	}

function remove_filter(id: Log::ID, name: string) : bool
	{
	delete filters[id, name];
	return Log::__remove_filter(id, name);
	}

function get_filter(id: Log::ID, name: string) : Filter
	{
	if ( [id, name] in filters )
		return filters[id, name];

	return no_filter;
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

