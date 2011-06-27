##! The Bro logging interface.
##!
##! See XXX for a introduction to Bro's logging framework.

module Log;

# Log::ID and Log::Writer are defined in bro.init due to circular dependencies.

export {
	## If true, is local logging is by default enabled for all filters.
	const enable_local_logging = T &redef;

	## If true, is remote logging is by default enabled for all filters.
	const enable_remote_logging = T &redef;

	## Default writer to use if a filter does not specify
	## anything else.
	const default_writer = WRITER_DATASERIES &redef;

	## Type defining the content of a logging stream.
	type Stream: record {
		## A record type defining the log's columns.
		columns: any;

		## Event that will be raised once for each log entry.
		## The event receives a single same parameter, an instance of type ``columns``.
		ev: any &optional;
	};

	## Filter customizing logging.
	type Filter: record {
		## Descriptive name to reference this filter.
		name: string;

		## The writer to use.
		writer: Writer &default=default_writer;

		## Predicate indicating whether a log entry should be recorded.
		## If not given, all entries are recorded.
		##
		## rec: An instance of the streams's ``columns`` type with its
		## fields set to the values to logged.
		##
		## Returns: True if the entry is to be recorded.
		pred: function(rec: any): bool &optional;

		## Output path for recording entries matching this
		## filter.
                ##
		## The specific interpretation of the string is up to
		## the used writer, and may for example be the destination
		## file name. Generally, filenames are expected to given
		## without any extensions; writers will add appropiate 
		## extensions automatically.
		path: string &optional;

		## A function returning the output path for recording entries
		## matching this filter. This is similar to ``path`` yet allows
		## to compute the string dynamically. It is ok to return
		## different strings for separate calls, but be careful: it's
		## easy to flood the disk by returning a new string for each
		## connection ...
		path_func: function(id: ID, path: string): string &optional;

		## Subset of column names to record. If not given, all
		## columns are recorded.
		include: set[string] &optional;

		## Subset of column names to exclude from recording. If not given,
		## all columns are recorded.
		exclude: set[string] &optional;

		## If true, entries are recorded locally.
		log_local: bool &default=enable_local_logging;

		## If true, entries are passed on to remote peers.
		log_remote: bool &default=enable_remote_logging;
	};

	# Log rotation support.

	## Information passed into rotation callback functions.
	type RotationInfo: record {
		writer: Writer;	##< Writer.
		path: string;	##< Original path value.
		open: time;	##< Time when opened.
		close: time;	##< Time when closed.
	};

	## Default rotation interval. Zero disables rotation.
	const default_rotation_interval = 0secs &redef;

	## Default naming suffix format. Uses a strftime() style.
	const default_rotation_date_format = "%y-%m-%d_%H.%M.%S" &redef;

	## Default postprocessor for writers outputting into files.
	const default_rotation_postprocessor = "" &redef;

	## Default function to construct the name of a rotated output file.
	## The default implementation appends info$date_fmt to the original
	## file name.
	##
	## info: Meta-data about the file to be rotated.
	global default_rotation_path_func: function(info: RotationInfo) : string &redef;

	## Type for controlling file rotation.
	type RotationControl: record  {
		## Rotation interval.
		interv: interval &default=default_rotation_interval;
		## Format for timestamps embedded into rotated file names.
		date_fmt: string &default=default_rotation_date_format;
		## Postprocessor process to run on rotate file.
		postprocessor: string &default=default_rotation_postprocessor;
	};

	## Specifies rotation parameters per ``(id, path)`` tuple.
	## If a pair is not found in this table, default values defined in
	## ``RotationControl`` are used.
	const rotation_control: table[Writer, string] of RotationControl &default=[] &redef;

	## Sentinel value for indicating that a filter was not found when looked up.
	const no_filter: Filter = [$name="<not found>"]; # Sentinel.

	# TODO: Document.
	global create_stream: function(id: ID, stream: Stream) : bool;
	global enable_stream: function(id: ID) : bool;
	global disable_stream: function(id: ID) : bool;
	global add_filter: function(id: ID, filter: Filter) : bool;
	global remove_filter: function(id: ID, name: string) : bool;
	global get_filter: function(id: ID, name: string) : Filter; # Returns no_filter if not found.
	global write: function(id: ID, columns: any) : bool;
	global set_buf: function(id: ID, buffered: bool): bool;
	global flush: function(id: ID): bool;
	global add_default_filter: function(id: ID) : bool;
	global remove_default_filter: function(id: ID) : bool;
}

# We keep a script-level copy of all filters so that we can manipulate them.
global filters: table[ID, string] of Filter;

@load logging.bif.bro # Needs Filter and Stream defined.

module Log;

function default_rotation_path_func(info: RotationInfo) : string
	{
	local date_fmt = rotation_control[info$writer, info$path]$date_fmt;
	return fmt("%s-%s", info$path, strftime(date_fmt, info$open));
	}

function create_stream(id: ID, stream: Stream) : bool
	{
	if ( ! __create_stream(id, stream) )
		return F;

	return add_default_filter(id);
	}

function disable_stream(id: ID) : bool
	{
	if ( ! __disable_stream(id) )
		return F;
	}
						   
function add_filter(id: ID, filter: Filter) : bool
	{
	filters[id, filter$name] = filter;
	return __add_filter(id, filter);
	}

function remove_filter(id: ID, name: string) : bool
	{
	delete filters[id, name];
	return __remove_filter(id, name);
	}

function get_filter(id: ID, name: string) : Filter
	{
	if ( [id, name] in filters )
		return filters[id, name];

	return no_filter;
	}

function write(id: ID, columns: any) : bool
	{
	return __write(id, columns);
	}

function set_buf(id: ID, buffered: bool): bool
	{
	return __set_buf(id, buffered);
	}

function flush(id: ID): bool
	{
	return __flush(id);
	}

function add_default_filter(id: ID) : bool
	{
	return add_filter(id, [$name="default"]);
	}

function remove_default_filter(id: ID) : bool
	{
	return remove_filter(id, "default");
	}

