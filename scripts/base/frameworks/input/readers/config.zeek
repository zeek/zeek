##! Interface for the config input reader.

module InputConfig;

export {
	## Separator between set and vector elements.
	## Please note that the separator has to be exactly one character long.
	const set_separator = Input::set_separator &redef;

	## String to use for empty fields.
	## By default this is the empty string, meaning that an empty input field
	## will result in an empty set.
	const empty_field = "" &redef;

	## Fail on file read problems. If set to true, the config
	## input reader will fail when encountering any problems
	## while reading a file different from invalid lines.
	## Examples of such problems are permission problems, or
	## missing files.
	## When set to false, these problems will be ignored. This
	## has an especially big effect for the REREAD mode, which will
	## seamlessly recover from read errors when a file is
	## only temporarily inaccessible. For MANUAL or STREAM files,
	## errors will most likely still be fatal since no automatic
	## re-reading of the file is attempted.
	## Individual readers can use a different value using
	## the $config table.
	const fail_on_file_problem = F &redef;

	## Event that is called when a config option is added or changes.
	##
	## Note - this does not track the reason for a change (new, changed),
	## and also does not track removals. If you need this, combine the event
	## with a table reader.
	##
	## name: Name of the input stream.
	##
	## source: Source of the input stream.
	##
	## id: ID of the configuration option being set.
	##
	## value: New value of the configuration option being set.
	global new_value: event(name: string, source: string, id: string, value: any);
}
