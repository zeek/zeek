##! The Bro logging interface.
##!
##! See :doc:`/frameworks/logging` for an introduction to Bro's
##! logging framework.

module Log;

# Log::ID and Log::Writer are defined in types.bif due to circular dependencies.

export {
	## If true, local logging is by default enabled for all filters.
	const enable_local_logging = T &redef;

	## If true, remote logging is by default enabled for all filters.
	const enable_remote_logging = T &redef;

	## Default writer to use if a filter does not specify
	## anything else.
	const default_writer = WRITER_ASCII &redef;

	## Default separator between fields for logwriters.
	## Can be overwritten by individual writers.
	const separator = "\t" &redef;

	## Separator between set elements.
	## Can be overwritten by individual writers.
	const set_separator = "," &redef;

	## String to use for empty fields. This should be different from
        ## *unset_field* to make the output unambiguous. 
	## Can be overwritten by individual writers.
	const empty_field = "(empty)" &redef;

	## String to use for an unset &optional field.
	## Can be overwritten by individual writers.
	const unset_field = "-" &redef;	

	## Type defining the content of a logging stream.
	type Stream: record {
		## A record type defining the log's columns.
		columns: any;

		## Event that will be raised once for each log entry.
		## The event receives a single same parameter, an instance of
		## type ``columns``.
		ev: any &optional;
	};

	## Builds the default path values for log filters if not otherwise
	## specified by a filter. The default implementation uses *id*
	## to derive a name.
	##
	## id: The ID associated with the log stream.
	##
	## path: A suggested path value, which may be either the filter's
	##       ``path`` if defined, else a previous result from the function.
	##       If no ``path`` is defined for the filter, then the first call
	##       to the function will contain an empty string.
	##
	## rec: An instance of the streams's ``columns`` type with its
	##      fields set to the values to be logged.
	##
	## Returns: The path to be used for the filter.
	global default_path_func: function(id: ID, path: string, rec: any) : string &redef;

	# Log rotation support.

	## Information passed into rotation callback functions.
	type RotationInfo: record {
		writer: Writer;		##< The :bro:type:`Log::Writer` being used.
		fname: string;		##< Full name of the rotated file.
		path: string;		##< Original path value.
		open: time;		##< Time when opened.
		close: time;		##< Time when closed.
		terminating: bool;	##< True if rotation occured due to Bro shutting down.
	};

	## Default rotation interval. Zero disables rotation.
	##
	## Note that this is overridden by the BroControl LogRotationInterval
	## option.
	const default_rotation_interval = 0secs &redef;

	## Default alarm summary mail interval. Zero disables alarm summary
	## mails.
	##
	## Note that this is overridden by the BroControl MailAlarmsInterval
	## option.
	const default_mail_alarms_interval = 0secs &redef;

	## Default naming format for timestamps embedded into filenames.
	## Uses a ``strftime()`` style.
	const default_rotation_date_format = "%Y-%m-%d-%H-%M-%S" &redef;

	## Default shell command to run on rotated files. Empty for none.
	const default_rotation_postprocessor_cmd = "" &redef;

	## Specifies the default postprocessor function per writer type.
	## Entries in this table are initialized by each writer type.
	const default_rotation_postprocessors: table[Writer] of function(info: RotationInfo) : bool &redef;

	## A filter type describes how to customize logging streams.
	type Filter: record {
		## Descriptive name to reference this filter.
		name: string;

		## The logging writer implementation to use.
		writer: Writer &default=default_writer;

		## Indicates whether a log entry should be recorded.
		## If not given, all entries are recorded.
		##
		## rec: An instance of the streams's ``columns`` type with its
		##      fields set to the values to logged.
		##
		## Returns: True if the entry is to be recorded.
		pred: function(rec: any): bool &optional;

		## Output path for recording entries matching this
		## filter.
		##
		## The specific interpretation of the string is up to
		## the used writer, and may for example be the destination
		## file name. Generally, filenames are expected to be given
		## without any extensions; writers will add appropiate
		## extensions automatically.
		##
		## If this path is found to conflict with another filter's
		## for the same writer type, it is automatically corrected
		## by appending "-N", where N is the smallest integer greater
		## or equal to 2 that allows the corrected path name to not
		## conflict with another filter's.
		path: string &optional;

		## A function returning the output path for recording entries
		## matching this filter. This is similar to *path* yet allows
		## to compute the string dynamically. It is ok to return
		## different strings for separate calls, but be careful: it's
		## easy to flood the disk by returning a new string for each
		## connection.
		##
		## id: The ID associated with the log stream.
		##
		## path: A suggested path value, which may be either the filter's
		##       ``path`` if defined, else a previous result from the
		##       function.  If no ``path`` is defined for the filter,
		##       then the first call to the function will contain an
		##       empty string.
		##
		## rec: An instance of the streams's ``columns`` type with its
		##      fields set to the values to be logged.
		##
		## Returns: The path to be used for the filter, which will be
		##          subject to the same automatic correction rules as
		##          the *path* field of :bro:type:`Log::Filter` in the
		##          case of conflicts with other filters trying to use
		##          the same writer/path pair.
		path_func: function(id: ID, path: string, rec: any): string &optional;

		## Subset of column names to record. If not given, all
		## columns are recorded.
		include: set[string] &optional;

		## Subset of column names to exclude from recording. If not
		## given, all columns are recorded.
		exclude: set[string] &optional;

		## If true, entries are recorded locally.
		log_local: bool &default=enable_local_logging;

		## If true, entries are passed on to remote peers.
		log_remote: bool &default=enable_remote_logging;

		## Rotation interval.
		interv: interval &default=default_rotation_interval;

		## Callback function to trigger for rotated files. If not set, the
		## default comes out of :bro:id:`Log::default_rotation_postprocessors`.
		postprocessor: function(info: RotationInfo) : bool &optional;

		## A key/value table that will be passed on to the writer.
		## Interpretation of the values is left to the writer, but
		## usually they will be used for configuration purposes.
		config: table[string] of string &default=table();
	};

	## Sentinel value for indicating that a filter was not found when looked up.
	const no_filter: Filter = [$name="<not found>"];

	## Creates a new logging stream with the default filter.
	##
	## id: The ID enum to be associated with the new logging stream.
	##
	## stream: A record defining the content that the new stream will log.
	##
	## Returns: True if a new logging stream was successfully created and
	##          a default filter added to it.
	##
	## .. bro:see:: Log::add_default_filter Log::remove_default_filter
	global create_stream: function(id: ID, stream: Stream) : bool;

	## Removes a logging stream completely, stopping all the threads.
	##
	## id: The ID enum to be associated with the new logging stream.
	##
	## Returns: True if a new stream was successfully removed.
	##
	## .. bro:see:: Log::create_stream
	global remove_stream: function(id: ID) : bool;

	## Enables a previously disabled logging stream.  Disabled streams
	## will not be written to until they are enabled again.  New streams
	## are enabled by default.
	##
	## id: The ID associated with the logging stream to enable.
	##
	## Returns: True if the stream is re-enabled or was not previously disabled.
	##
	## .. bro:see:: Log::disable_stream
	global enable_stream: function(id: ID) : bool;

	## Disables a currently enabled logging stream.  Disabled streams
	## will not be written to until they are enabled again.  New streams
	## are enabled by default.
	##
	## id: The ID associated with the logging stream to disable.
	##
	## Returns: True if the stream is now disabled or was already disabled.
	##
	## .. bro:see:: Log::enable_stream
	global disable_stream: function(id: ID) : bool;

	## Adds a custom filter to an existing logging stream.  If a filter
	## with a matching ``name`` field already exists for the stream, it
	## is removed when the new filter is successfully added.
	##
	## id: The ID associated with the logging stream to filter.
	##
	## filter: A record describing the desired logging parameters.
	##
	## Returns: True if the filter was successfully added, false if
	##          the filter was not added or the *filter* argument was not
	##          the correct type.
	##
	## .. bro:see:: Log::remove_filter Log::add_default_filter
	##    Log::remove_default_filter
	global add_filter: function(id: ID, filter: Filter) : bool;

	## Removes a filter from an existing logging stream.
	##
	## id: The ID associated with the logging stream from which to
	##     remove a filter.
	##
	## name: A string to match against the ``name`` field of a
	##       :bro:type:`Log::Filter` for identification purposes.
	##
	## Returns: True if the logging stream's filter was removed or
	##          if no filter associated with *name* was found.
	##
	## .. bro:see:: Log::remove_filter Log::add_default_filter
	##    Log::remove_default_filter
	global remove_filter: function(id: ID, name: string) : bool;

	## Gets a filter associated with an existing logging stream.
	##
	## id: The ID associated with a logging stream from which to
	##     obtain one of its filters.
	##
	## name: A string to match against the ``name`` field of a
	##       :bro:type:`Log::Filter` for identification purposes.
	##
	## Returns: A filter attached to the logging stream *id* matching
	##          *name* or, if no matches are found returns the
	##          :bro:id:`Log::no_filter` sentinel value.
	##
	## .. bro:see:: Log::add_filter Log::remove_filter Log::add_default_filter
	##              Log::remove_default_filter
	global get_filter: function(id: ID, name: string) : Filter;

	## Writes a new log line/entry to a logging stream.
	##
	## id: The ID associated with a logging stream to be written to.
	##
	## columns: A record value describing the values of each field/column
	##          to write to the log stream.
	##
	## Returns: True if the stream was found and no error occurred in writing
	##          to it or if the stream was disabled and nothing was written.
	##          False if the stream was not found, or the *columns*
	##          argument did not match what the stream was initially defined
	##          to handle, or one of the stream's filters has an invalid
	##          ``path_func``.
	##
	## .. bro:see: Log::enable_stream Log::disable_stream
	global write: function(id: ID, columns: any) : bool;

	## Sets the buffering status for all the writers of a given logging stream.
	## A given writer implementation may or may not support buffering and if
	## it doesn't then toggling buffering with this function has no effect.
	##
	## id: The ID associated with a logging stream for which to
	##     enable/disable buffering.
	##
	## buffered: Whether to enable or disable log buffering.
	##
	## Returns: True if buffering status was set, false if the logging stream
	##          does not exist.
	##
	## .. bro:see:: Log::flush
	global set_buf: function(id: ID, buffered: bool): bool;

	## Flushes any currently buffered output for all the writers of a given
	## logging stream.
	##
	## id: The ID associated with a logging stream for which to flush buffered
	##     data.
	##
	## Returns: True if all writers of a log stream were signalled to flush
	##          buffered data or if the logging stream is disabled,
	##          false if the logging stream does not exist.
	##
	## .. bro:see:: Log::set_buf Log::enable_stream Log::disable_stream
	global flush: function(id: ID): bool;

	## Adds a default :bro:type:`Log::Filter` record with ``name`` field
	## set as "default" to a given logging stream.
	##
	## id: The ID associated with a logging stream for which to add a default
	##     filter.
	##
	## Returns: The status of a call to :bro:id:`Log::add_filter` using a
	##          default :bro:type:`Log::Filter` argument with ``name`` field
	##          set to "default".
	##
	## .. bro:see:: Log::add_filter Log::remove_filter
	##    Log::remove_default_filter
	global add_default_filter: function(id: ID) : bool;

	## Removes the :bro:type:`Log::Filter` with ``name`` field equal to
	## "default".
	##
	## id: The ID associated with a logging stream from which to remove the
	##     default filter.
	##
	## Returns: The status of a call to :bro:id:`Log::remove_filter` using
	##          "default" as the argument.
	##
	## .. bro:see:: Log::add_filter Log::remove_filter Log::add_default_filter
	global remove_default_filter: function(id: ID) : bool;

	## Runs a command given by :bro:id:`Log::default_rotation_postprocessor_cmd`
	## on a rotated file.  Meant to be called from postprocessor functions
	## that are added to :bro:id:`Log::default_rotation_postprocessors`.
	##
	## info: A record holding meta-information about the log being rotated.
	##
	## npath: The new path of the file (after already being rotated/processed
	##        by writer-specific postprocessor as defined in
	##        :bro:id:`Log::default_rotation_postprocessors`).
	##
	## Returns: True when :bro:id:`Log::default_rotation_postprocessor_cmd`
	##          is empty or the system command given by it has been invoked
	##          to postprocess a rotated log file.
	##
	## .. bro:see:: Log::default_rotation_date_format
	##    Log::default_rotation_postprocessor_cmd
	##    Log::default_rotation_postprocessors
	global run_rotation_postprocessor_cmd: function(info: RotationInfo, npath: string) : bool;

	## The streams which are currently active and not disabled.
	## This table is not meant to be modified by users!  Only use it for
	## examining which streams are active.
	global active_streams: table[ID] of Stream = table();
}

# We keep a script-level copy of all filters so that we can manipulate them.
global filters: table[ID, string] of Filter;

@load base/bif/logging.bif # Needs Filter and Stream defined.

module Log;

# Used internally by the log manager.
function __default_rotation_postprocessor(info: RotationInfo) : bool
	{
	if ( info$writer in default_rotation_postprocessors )
		return default_rotation_postprocessors[info$writer](info);
	else
		# Return T by default so that postprocessor-less writers don't shutdown.
		return T;
	}

function default_path_func(id: ID, path: string, rec: any) : string
	{
	# The suggested path value is a previous result of this function
	# or a filter path explicitly set by the user, so continue using it.
	if ( path != "" )
		return path;

	local id_str = fmt("%s", id);

	local parts = split1(id_str, /::/);
	if ( |parts| == 2 )
		{
		# Example: Notice::LOG -> "notice"
		if ( parts[2] == "LOG" )
			{
			local module_parts = split_n(parts[1], /[^A-Z][A-Z][a-z]*/, T, 4);
			local output = "";
			if ( 1 in module_parts )
				output = module_parts[1];
			if ( 2 in module_parts && module_parts[2] != "" )
				output = cat(output, sub_bytes(module_parts[2],1,1), "_", sub_bytes(module_parts[2], 2, |module_parts[2]|));
			if ( 3 in module_parts && module_parts[3] != "" )
				output = cat(output, "_", module_parts[3]);
			if ( 4 in module_parts && module_parts[4] != "" )
				output = cat(output, sub_bytes(module_parts[4],1,1), "_", sub_bytes(module_parts[4], 2, |module_parts[4]|));
			return to_lower(output);
			}

		# Example: Notice::POLICY_LOG -> "notice_policy"
		if ( /_LOG$/ in parts[2] )
			parts[2] = sub(parts[2], /_LOG$/, "");

		return cat(to_lower(parts[1]),"_",to_lower(parts[2]));
		}
	else
		return to_lower(id_str);
	}

# Run post-processor on file. If there isn't any postprocessor defined,
# we move the file to a nicer name.
function run_rotation_postprocessor_cmd(info: RotationInfo, npath: string) : bool
	{
	local pp_cmd = default_rotation_postprocessor_cmd;

	if ( pp_cmd == "" )
		return T;

	# Turn, e.g., Log::WRITER_ASCII into "ascii".
	local writer = subst_string(to_lower(fmt("%s", info$writer)), "log::writer_", "");

	# The date format is hard-coded here to provide a standardized
	# script interface.
	system(fmt("%s %s %s %s %s %d %s",
               pp_cmd, npath, info$path,
               strftime("%y-%m-%d_%H.%M.%S", info$open),
               strftime("%y-%m-%d_%H.%M.%S", info$close),
               info$terminating, writer));

	return T;
	}

function create_stream(id: ID, stream: Stream) : bool
	{
	if ( ! __create_stream(id, stream) )
		return F;

	active_streams[id] = stream;

	return add_default_filter(id);
	}

function remove_stream(id: ID) : bool
	{
	delete active_streams[id];
	return __remove_stream(id);
	}

function disable_stream(id: ID) : bool
	{
	delete active_streams[id];

	return __disable_stream(id);
	}

function add_filter(id: ID, filter: Filter) : bool
	{
	# This is a work-around for the fact that we can't forward-declare
	# the default_path_func and then use it as &default in the record
	# definition.
	if ( ! filter?$path_func )
		filter$path_func = default_path_func;

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
