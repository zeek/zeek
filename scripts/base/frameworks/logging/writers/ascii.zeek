##! Interface for the ASCII log writer.  Redefinable options are available
##! to tweak the output format of ASCII logs.
##!
##! The ASCII writer currently supports one writer-specific per-filter config
##! option: setting ``tsv`` to the string ``T`` turns the output into
##! "tab-separated-value" mode where only a single header row with the column
##! names is printed out as meta information, with no "# fields" prepended; no
##! other meta data gets included in that mode.  Example filter using this::
##!
##!    local f: Log::Filter = [$name = "my-filter",
##!                            $writer = Log::WRITER_ASCII,
##!                            $config = table(["tsv"] = "T")];
##!

module LogAscii;

export {
	## If true, output everything to stdout rather than
	## into files. This is primarily for debugging purposes.
	##
	## This option is also available as a per-filter ``$config`` option.
	const output_to_stdout = F &redef;

	## If true, the default will be to write logs in a JSON format.
	##
	## This option is also available as a per-filter ``$config`` option.
	const use_json = F &redef;

	## If true, detect log files that did not get properly rotated
	## by a previous Zeek process (e.g. due to crash) and rotate them.
	##
	## This requires a positive rotation interval to be configured
	## to have an effect.  E.g. via :zeek:see:`Log::default_rotation_interval`
	## or the *interv* field of a :zeek:see:`Log::Filter`.
	const enable_leftover_log_rotation = F &redef;

	## If true, valid UTF-8 sequences will pass through unescaped and be
	## written into logs.
	##
	## This option is also available as a per-filter ``$config`` option.
	const enable_utf_8 = T &redef;

	## Define the gzip level to compress the logs.  If 0, then no gzip
	## compression is performed. Enabling compression also changes
	## the log file name extension to include the value of
	## :zeek:see:`LogAscii::gzip_file_extension`.
	##
	## This option is also available as a per-filter ``$config`` option.
	const gzip_level = 0 &redef;

	## Define the file extension used when compressing log files when
	## they are created with the :zeek:see:`LogAscii::gzip_level` option.
	##
	## This option is also available as a per-filter ``$config`` option.
	const gzip_file_extension = "gz" &redef;

	## Define the default logging directory. If empty, logs are written
	## to the current working directory.
	##
	const logdir = "" &redef;

	## Format of timestamps when writing out JSON. By default, the JSON
	## formatter will use double values for timestamps which represent the
	## number of seconds from the UNIX epoch.
	##
	## This option is also available as a per-filter ``$config`` option.
	const json_timestamps: JSON::TimestampFormat = JSON::TS_EPOCH &redef;

	## If true, include lines with log meta information such as column names
	## with types, the values of ASCII logging options that are in use, and
	## the time when the file was opened and closed (the latter at the end).
	##
	## If writing in JSON format, this is implicitly disabled.
	const include_meta = T &redef;

	## Prefix for lines with meta information.
	##
	## This option is also available as a per-filter ``$config`` option.
	const meta_prefix = "#" &redef;

	## Separator between fields.
	##
	## This option is also available as a per-filter ``$config`` option.
	const separator = Log::separator &redef;

	## Separator between set elements.
	##
	## This option is also available as a per-filter ``$config`` option.
	const set_separator = Log::set_separator &redef;

	## String to use for empty fields. This should be different from
	## *unset_field* to make the output unambiguous.
	##
	## This option is also available as a per-filter ``$config`` option.
	const empty_field = Log::empty_field &redef;

	## String to use for an unset &optional field.
	##
	## This option is also available as a per-filter ``$config`` option.
	const unset_field = Log::unset_field &redef;
}
