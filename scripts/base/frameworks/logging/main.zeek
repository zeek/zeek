##! The Zeek logging interface.
##!
##! See :doc:`/frameworks/logging` for an introduction to Zeek's
##! logging framework.

module Log;

export {
	## Type that defines an ID unique to each log stream. Scripts creating new
	## log streams need to redef this enum to add their own specific log ID.
	## The log ID implicitly determines the default name of the generated log
	## file.
	type Log::ID: enum {
		## Dummy place-holder.
		UNKNOWN,
		## Print statements that have been redirected to a log stream.
		PRINTLOG
	};

	## If true, local logging is by default enabled for all filters.
	const enable_local_logging = T &redef;

	## If true, remote logging is by default enabled for all filters.
	const enable_remote_logging = T &redef;

	## Default writer to use if a filter does not specify anything else.
	const default_writer = WRITER_ASCII &redef;

	## Default logging directory. An empty string implies using the
	## current working directory.
	##
	## This directory is also used for rotated logs in cases where
	## :zeek:see:`Log::rotation_format_func` returns a record with
	## an empty or unset ``dir`` field.
	const default_logdir = "" &redef;

	## Default separator to use between fields.
	## Individual writers can use a different value.
	const separator = "\t" &redef;

	## Default separator to use between elements of a set.
	## Individual writers can use a different value.
	const set_separator = "," &redef;

	## Default string to use for empty fields. This should be different
	## from *unset_field* to make the output unambiguous.
	## Individual writers can use a different value.
	const empty_field = "(empty)" &redef;

	## Default string to use for an unset &optional field.
	## Individual writers can use a different value.
	const unset_field = "-" &redef;

	## Builds the default path values for log filters if not otherwise
	## specified by a filter. The default implementation uses *id*
	## to derive a name.  Upon adding a filter to a stream, if neither
	## ``path`` nor ``path_func`` is explicitly set by them, then
	## this function is used as the ``path_func``.
	##
	## id: The ID associated with the log stream.
	##
	## path: A suggested path value, which may be either the filter's
	##       ``path`` if defined, else a previous result from the function.
	##       If no ``path`` is defined for the filter, then the first call
	##       to the function will contain an empty string.
	##
	## rec: An instance of the stream's ``columns`` type with its
	##      fields set to the values to be logged.
	##
	## Returns: The path to be used for the filter.
	global default_path_func: function(id: ID, path: string, rec: any) : string &redef;

	## If :zeek:see:`Log::print_to_log` is set to redirect, ``print`` statements will
	## automatically populate log entries with the fields contained in this record.
	type PrintLogInfo: record {
		## The network time at which the print statement was executed.
		ts:                  time              &log;
		## Set of strings passed to the print statement.
		vals:                string_vec        &log;
	};

	## Configurations for :zeek:see:`Log::print_to_log`
	type PrintLogType: enum {
		## No redirection of ``print`` statements.
		REDIRECT_NONE,
		## Redirection of those ``print`` statements that were being logged to stdout,
		## leaving behind those set to go to other specific files.
		REDIRECT_STDOUT,
		## Redirection of all ``print`` statements.
		REDIRECT_ALL
	};

	## Event for accessing logged print records.
	global log_print: event(rec: PrintLogInfo);

	## Set configuration for ``print`` statements redirected to logs.
	const print_to_log: PrintLogType = REDIRECT_NONE &redef;

	## If :zeek:see:`Log::print_to_log` is enabled to write to a print log,
	## this is the path to which the print Log Stream writes to
	const print_log_path = "print" &redef;

	# Log rotation support.

	## Information passed into rotation callback functions.
	type RotationInfo: record {
		writer: Writer;		##< The log writer being used.
		fname: string;		##< Full name of the rotated file.
		path: string;		##< Original path value.
		open: time;		##< Time when opened.
		close: time;		##< Time when closed.
		terminating: bool;	##< True if rotation occurred due to Zeek shutting down.
	};

	## The function type for log rotation post processors.
	type RotationPostProcessorFunc: function(info: Log::RotationInfo): bool;

	## Information passed into rotation format callback function given by
	## :zeek:see:`Log::rotation_format_func`.
	type RotationFmtInfo: record {
		writer: Writer;    ##< The log writer being used.
		path: string;      ##< Original path value.
		open: time;        ##< Time when opened.
		close: time;       ##< Time when closed.
		terminating: bool; ##< True if rotation occurred due to Zeek shutting down.
		## The postprocessor function that will be called after rotation.
		postprocessor: RotationPostProcessorFunc &optional;
	};

	## Default rotation interval to use for filters that do not specify
	## an interval. Zero disables rotation.
	##
	## Note that this is overridden by the ZeekControl LogRotationInterval
	## option.
	const default_rotation_interval = 0secs &redef;

	## Default rotation directory to use for the *dir* field of
	## :zeek:see:`Log::RotationPath` during calls to
	## :zeek:see:`Log::rotation_format_func`.  An empty string implies
	## using the current working directory;
	option default_rotation_dir = "";

	## A log file rotation path specification that's returned by the
	## user-customizable :zeek:see:`Log::rotation_format_func`.
	type RotationPath: record {
		## A directory to rotate the log to.  This directory is created
		## just-in-time, as the log rotation is about to happen.  If it
		## cannot be created, an error is emitted and the rotation process
		## tries to proceed with rotation inside the working directory.  When
		## setting this field, beware that renaming files across file systems
		## will generally fail.
		dir: string &default = default_rotation_dir;

		## A base name to use for the rotated log.  Log writers may later
		## append a file extension of their choosing to this user-chosen
		## base (e.g. if using the default ASCII writer and you want
		## rotated files of the format "foo-<date>.log", then this basename
		## can be set to "foo-<date>" and the ".log" is added later (there's
		## also generally means of customizing the file extension, too,
		## like the ``ZEEK_LOG_SUFFIX`` environment variable or
		## writer-dependent configuration options.
		file_basename: string;
	};

	## A function that one may use to customize log file rotation paths.
	## Note that the "fname" field of the *ri* argument is always an
	## empty string for the purpose of this function call (i.e. the full
	## file name is not determined yet).
	const rotation_format_func: function(ri: RotationFmtInfo): RotationPath &redef;

	## Default naming format for timestamps embedded into filenames.
	## Uses a ``strftime()`` style.
	const default_rotation_date_format = "%Y-%m-%d-%H-%M-%S" &redef;

	## Default shell command to run on rotated files. Empty for none.
	const default_rotation_postprocessor_cmd = "" &redef;

	## Specifies the default postprocessor function per writer type.
	## Entries in this table are initialized by each writer type.
	const default_rotation_postprocessors: table[Writer] of function(info: RotationInfo) : bool &redef;

	## Default alarm summary mail interval. Zero disables alarm summary
	## mails.
	##
	## Note that this is overridden by the ZeekControl MailAlarmsInterval
	## option.
	const default_mail_alarms_interval = 0secs &redef;

	## Default field name mapping for renaming fields in a logging framework
	## filter.  This is typically used to ease integration with external
	## data storage and analysis systems.
	const default_field_name_map: table[string] of string = table() &redef;

	## Default separator for log field scopes when logs are unrolled and
	## flattened.  This will be the string between field name components.
	## For example, setting this to "_" will cause the typical field
	## "id.orig_h" to turn into "id_orig_h".
	const default_scope_sep = "." &redef;

	## A prefix for extension fields which can be optionally prefixed
	## on all log lines by setting the `ext_func` field in the
	## log filter.
	const Log::default_ext_prefix: string = "_" &redef;

	## Default log extension function in the case that you would like to
	## apply the same extensions to all logs.  The function *must* return
	## a record with all of the fields to be included in the log. The
	## default function included here does not return a value, which indicates
	## that no extensions are added.
	const Log::default_ext_func: function(path: string): any =
		function(path: string) { } &redef;

	## A filter type describes how to customize logging streams.
	type Filter: record {
		## Descriptive name to reference this filter.
		name: string;

		## The logging writer implementation to use.
		writer: Writer &default=default_writer;

		## Output path for recording entries matching this
		## filter.
		##
		## The specific interpretation of the string is up to the
		## logging writer, and may for example be the destination
		## file name. Generally, filenames are expected to be given
		## without any extensions; writers will add appropriate
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
		## connection.  Upon adding a filter to a stream, if neither
		## ``path`` nor ``path_func`` is explicitly set by them, then
		## :zeek:see:`Log::default_path_func` is used.
		##
		## id: The ID associated with the log stream.
		##
		## path: A suggested path value, which may be either the filter's
		##       ``path`` if defined, else a previous result from the
		##       function.  If no ``path`` is defined for the filter,
		##       then the first call to the function will contain an
		##       empty string.
		##
		## rec: An instance of the stream's ``columns`` type with its
		##      fields set to the values to be logged.
		##
		## Returns: The path to be used for the filter, which will be
		##          subject to the same automatic correction rules as
		##          the *path* field of :zeek:type:`Log::Filter` in the
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

		## Field name map to rename fields before the fields are written
		## to the output.
		field_name_map: table[string] of string &default=default_field_name_map;

		## A string that is used for unrolling and flattening field names
		## for nested record types.
		scope_sep: string &default=default_scope_sep;

		## Default prefix for all extension fields. It's typically
		## prudent to set this to something that Zeek's logging
		## framework can't normally write out in a field name.
		ext_prefix: string &default=default_ext_prefix;

		## Function to collect a log extension value.  If not specified,
		## no log extension will be provided for the log.
		## The return value from the function *must* be a record.
		ext_func: function(path: string): any &default=default_ext_func;

		## Rotation interval. Zero disables rotation.
		interv: interval &default=default_rotation_interval;

		## Callback function to trigger for rotated files. If not set, the
		## default comes out of :zeek:id:`Log::default_rotation_postprocessors`.
		postprocessor: function(info: RotationInfo) : bool &optional;

		## A key/value table that will be passed on to the writer.
		## Interpretation of the values is left to the writer, but
		## usually they will be used for configuration purposes.
		config: table[string] of string &default=table();
	};

	## A hook type to implement filtering policy. Hook handlers run
	## on each log record. They can implement arbitrary per-record
	## processing, alter the log record, or veto the writing of the
	## given record by breaking from the hook handler.
	##
	## rec: An instance of the stream's ``columns`` type with its
	##      fields set to the values to be logged.
	##
	## id: The ID associated with the logging stream the filter
	##     belongs to.
	type StreamPolicyHook: hook(rec: any, id: ID);

	## A hook type to implement filtering policy at log filter
	## granularity. Like :zeek:see:`Log::StreamPolicyHook`, these can
	## implement added functionality, alter it prior to logging, or
	## veto the write. These hooks run at log filter granularity,
	## so get a :zeek:see:`Log::Filter` instance as additional
	## argument. You can pass additional state into the hook via the
	## the filter$config table.
	##
	## rec: An instance of the stream's ``columns`` type with its
	##      fields set to the values to be logged.
	##
	## id: The ID associated with the logging stream the filter
	##     belongs to.
	##
	## filter: The :zeek:type:`Log::Filter` instance that steers
	##         the output of the given log record.
	type PolicyHook: hook(rec: any, id: ID, filter: Filter);

	# To allow Filters to have a policy hook that refers to
	# Filters, the Filter type must exist. So redef now to add the
	# hook to the record.
	redef record Filter += {
		## Policy hooks can adjust log entry values and veto
		## the writing of a log entry for the record passed
		## into it. Any hook that breaks from its body signals
		## that Zeek won't log the entry passed into it.
		##
		## When no policy hook is defined, the filter inherits
		## the hook from the stream it's associated with.
		policy: PolicyHook &optional;
	};

	## Type defining the content of a logging stream.
	type Stream: record {
		## A record type defining the log's columns.
		columns: any;

		## Event that will be raised once for each log entry.
		## The event receives a single same parameter, an instance of
		## type ``columns``.
		ev: any &optional;

		## A path that will be inherited by any filters added to the
		## stream which do not already specify their own path.
		path: string &optional;

		## Policy hooks can adjust log records and veto their
		## writing. Any hook handler that breaks from its body
		## signals that Zeek won't log the entry passed into
		## it. You can pass arbitrary state into the hook via
		## the filter instance and its config table.
		##
		## New Filters created for this stream will inherit
		## this policy hook, unless they provide their own.
		policy: PolicyHook &optional;
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
	## .. zeek:see:: Log::add_default_filter Log::remove_default_filter
	global create_stream: function(id: ID, stream: Stream) : bool;

	## Removes a logging stream completely, stopping all the threads.
	##
	## id: The ID associated with the logging stream.
	##
	## Returns: True if the stream was successfully removed.
	##
	## .. zeek:see:: Log::create_stream
	global remove_stream: function(id: ID) : bool;

	## Enables a previously disabled logging stream.  Disabled streams
	## will not be written to until they are enabled again.  New streams
	## are enabled by default.
	##
	## id: The ID associated with the logging stream to enable.
	##
	## Returns: True if the stream is re-enabled or was not previously disabled.
	##
	## .. zeek:see:: Log::disable_stream
	global enable_stream: function(id: ID) : bool;

	## Disables a currently enabled logging stream.  Disabled streams
	## will not be written to until they are enabled again.  New streams
	## are enabled by default.
	##
	## id: The ID associated with the logging stream to disable.
	##
	## Returns: True if the stream is now disabled or was already disabled.
	##
	## .. zeek:see:: Log::enable_stream
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
	## .. zeek:see:: Log::remove_filter Log::add_default_filter
	##    Log::remove_default_filter Log::get_filter Log::get_filter_names
	global add_filter: function(id: ID, filter: Filter) : bool;

	## Removes a filter from an existing logging stream.
	##
	## id: The ID associated with the logging stream from which to
	##     remove a filter.
	##
	## name: A string to match against the ``name`` field of a
	##       :zeek:type:`Log::Filter` for identification purposes.
	##
	## Returns: True if the logging stream's filter was removed or
	##          if no filter associated with *name* was found.
	##
	## .. zeek:see:: Log::remove_filter Log::add_default_filter
	##    Log::remove_default_filter Log::get_filter Log::get_filter_names
	global remove_filter: function(id: ID, name: string) : bool;

	## Gets the names of all filters associated with an existing
	## logging stream.
	##
	## id: The ID of a logging stream from which to obtain the list
	##     of filter names.
	##
	## Returns: The set of filter names associated with the stream.
	##
	## ..zeek:see:: Log::remove_filter Log::add_default_filter
	##   Log::remove_default_filter Log::get_filter
	global get_filter_names: function(id: ID) : set[string];

	## Gets a filter associated with an existing logging stream.
	##
	## id: The ID associated with a logging stream from which to
	##     obtain one of its filters.
	##
	## name: A string to match against the ``name`` field of a
	##       :zeek:type:`Log::Filter` for identification purposes.
	##
	## Returns: A filter attached to the logging stream *id* matching
	##          *name* or, if no matches are found returns the
	##          :zeek:id:`Log::no_filter` sentinel value.
	##
	## .. zeek:see:: Log::add_filter Log::remove_filter Log::add_default_filter
	##              Log::remove_default_filter Log::get_filter_names
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
	## .. zeek:see:: Log::enable_stream Log::disable_stream
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
	## .. zeek:see:: Log::flush
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
	## .. zeek:see:: Log::set_buf Log::enable_stream Log::disable_stream
	global flush: function(id: ID): bool;

	## Adds a default :zeek:type:`Log::Filter` record with ``name`` field
	## set as "default" to a given logging stream.
	##
	## id: The ID associated with a logging stream for which to add a default
	##     filter.
	##
	## Returns: The status of a call to :zeek:id:`Log::add_filter` using a
	##          default :zeek:type:`Log::Filter` argument with ``name`` field
	##          set to "default".
	##
	## .. zeek:see:: Log::add_filter Log::remove_filter
	##    Log::remove_default_filter
	global add_default_filter: function(id: ID) : bool;

	## Removes the :zeek:type:`Log::Filter` with ``name`` field equal to
	## "default".
	##
	## id: The ID associated with a logging stream from which to remove the
	##     default filter.
	##
	## Returns: The status of a call to :zeek:id:`Log::remove_filter` using
	##          "default" as the argument.
	##
	## .. zeek:see:: Log::add_filter Log::remove_filter Log::add_default_filter
	global remove_default_filter: function(id: ID) : bool;

	## Runs a command given by :zeek:id:`Log::default_rotation_postprocessor_cmd`
	## on a rotated file.  Meant to be called from postprocessor functions
	## that are added to :zeek:id:`Log::default_rotation_postprocessors`.
	##
	## info: A record holding meta-information about the log being rotated.
	##
	## npath: The new path of the file (after already being rotated/processed
	##        by writer-specific postprocessor as defined in
	##        :zeek:id:`Log::default_rotation_postprocessors`).
	##
	## Returns: True when :zeek:id:`Log::default_rotation_postprocessor_cmd`
	##          is empty or the system command given by it has been invoked
	##          to postprocess a rotated log file.
	##
	## .. zeek:see:: Log::default_rotation_date_format
	##    Log::default_rotation_postprocessor_cmd
	##    Log::default_rotation_postprocessors
	global run_rotation_postprocessor_cmd: function(info: RotationInfo, npath: string) : bool;

	## The streams which are currently active and not disabled.
	## This table is not meant to be modified by users!  Only use it for
	## examining which streams are active.
	global active_streams: table[ID] of Stream = table();

	## The global log policy hook. The framework invokes this hook for any
	## log write, prior to iterating over the stream's associated filters.
	## As with filter-specific hooks, breaking from the hook vetoes writing
	## of the given log record. Note that filter-level policy hooks still get
	## invoked after the global hook vetos, but they cannot "un-veto" the write.
	global log_stream_policy: Log::StreamPolicyHook;
}

global all_streams: table[ID] of Stream = table();

global stream_filters: table[ID] of set[string] = table();

# We keep a script-level copy of all filters so that we can manipulate them.
global filters: table[ID, string] of Filter;

@load base/bif/logging.bif # Needs Filter and Stream defined.

module Log;

# Used internally by the log manager.
function __default_rotation_postprocessor(info: RotationInfo) : bool &is_used
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

	local parts = split_string1(id_str, /::/);
	if ( |parts| == 2 )
		{
		# Example: Notice::LOG -> "notice"
		if ( parts[1] == "LOG" )
			{
			local module_parts = split_string_n(parts[0], /[^A-Z][A-Z][a-z]*/, T, 4);
			local output = "";
			if ( 0 in module_parts )
				output = module_parts[0];
			if ( 1 in module_parts && module_parts[1] != "" )
				output = cat(output, sub_bytes(module_parts[1],1,1), "_", sub_bytes(module_parts[1], 2, |module_parts[1]|));
			if ( 2 in module_parts && module_parts[2] != "" )
				output = cat(output, "_", module_parts[2]);
			if ( 3 in module_parts && module_parts[3] != "" )
				output = cat(output, sub_bytes(module_parts[3],1,1), "_", sub_bytes(module_parts[3], 2, |module_parts[3]|));
			return to_lower(output);
			}

		# Example: Notice::POLICY_LOG -> "notice_policy"
		if ( /_LOG$/ in parts[1] )
			parts[1] = sub(parts[1], /_LOG$/, "");

		return cat(to_lower(parts[0]),"_",to_lower(parts[1]));
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
               pp_cmd, safe_shell_quote(npath), safe_shell_quote(info$path),
               strftime("%y-%m-%d_%H.%M.%S", info$open),
               strftime("%y-%m-%d_%H.%M.%S", info$close),
               info$terminating, writer));

	return T;
	}

# Default function to postprocess a rotated ASCII log file. It simply
# runs the writer's default postprocessor command on it.
function default_ascii_rotation_postprocessor_func(info: Log::RotationInfo): bool
	{
	# Run default postprocessor.
	return Log::run_rotation_postprocessor_cmd(info, info$fname);
	}

redef Log::default_rotation_postprocessors += {
	[Log::WRITER_ASCII] = default_ascii_rotation_postprocessor_func
};

function Log::rotation_format_func(ri: Log::RotationFmtInfo): Log::RotationPath
	{
	local rval: Log::RotationPath;
	local open_str: string;

	# The reason for branching here is historical:
	# the default format path before the intro of Log::rotation_format_func
	# always separated the path from open-time using a '-', but ASCII's
	# default postprocessor chose to rename using a '.' separator.  It also
	# chose a different date format.
	if ( ri$postprocessor == __default_rotation_postprocessor &&
	    ri$writer == WRITER_ASCII &&
	    ri$writer in default_rotation_postprocessors &&
	    default_rotation_postprocessors[WRITER_ASCII] == default_ascii_rotation_postprocessor_func)
		{
		open_str = strftime(Log::default_rotation_date_format, ri$open);
		rval = RotationPath($file_basename=fmt("%s.%s", ri$path, open_str));
		}
	else
		{
		open_str = strftime("%y-%m-%d_%H.%M.%S", ri$open);
		rval = RotationPath($file_basename=fmt("%s-%s", ri$path, open_str));
		}

	return rval;
	}

function create_stream(id: ID, stream: Stream) : bool
	{
	if ( ! __create_stream(id, stream) )
		return F;

	active_streams[id] = stream;
	all_streams[id] = stream;

	return add_default_filter(id);
	}

function remove_stream(id: ID) : bool
	{
	delete active_streams[id];
	delete all_streams[id];

	if ( id in stream_filters )
		{
		for ( i in stream_filters[id] )
			delete filters[id, i];

		delete stream_filters[id];
		}
	return __remove_stream(id);
	}

function disable_stream(id: ID) : bool
	{
	delete active_streams[id];
	return __disable_stream(id);
	}

function enable_stream(id: ID) : bool
	{
	if ( ! __enable_stream(id) )
		return F;

	if ( id in all_streams )
		active_streams[id] = all_streams[id];

	return T;
	}

# convenience function to add a filter name to stream_filters
function add_stream_filters(id: ID, name: string)
	{
	if ( id in stream_filters )
		add stream_filters[id][name];
	else
		stream_filters[id] = set(name);
	}

function add_filter(id: ID, filter: Filter) : bool
	{
	local stream = all_streams[id];

	if ( stream?$path && ! filter?$path )
		filter$path = stream$path;

	if ( ! filter?$path && ! filter?$path_func )
		filter$path_func = default_path_func;

	local res = __add_filter(id, filter);
	if ( res )
		{
		add_stream_filters(id, filter$name);
		filters[id, filter$name] = filter;
		}
	return res;
	}

function remove_filter(id: ID, name: string) : bool
	{
	if ( id in stream_filters )
		delete stream_filters[id][name];

	delete filters[id, name];

	return __remove_filter(id, name);
	}

function get_filter(id: ID, name: string) : Filter
	{
	if ( [id, name] in filters )
		return filters[id, name];

	return no_filter;
	}

function get_filter_names(id: ID) : set[string]
	{
	if ( id in stream_filters )
		return stream_filters[id];
	else
		return set();
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

event zeek_init() &priority=5
	{
	if ( print_to_log != REDIRECT_NONE )
		Log::create_stream(PRINTLOG, [$columns=PrintLogInfo, $ev=log_print, $path=print_log_path]);
	}
