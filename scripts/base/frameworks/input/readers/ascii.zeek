##! Interface for the ascii input reader.
##!
##! The defaults are set to match Zeek's ASCII output.

module InputAscii;

export {
	## Separator between fields.
	## Please note that the separator has to be exactly one character long.
	const separator = Input::separator &redef;

	## Separator between set and vector elements.
	## Please note that the separator has to be exactly one character long.
	const set_separator = Input::set_separator &redef;

	## String to use for empty fields.
	const empty_field = Input::empty_field &redef;

	## String to use for an unset &optional field.
	const unset_field = Input::unset_field &redef;

	## Fail on invalid lines. If set to false, the ascii
	## input reader will jump over invalid lines, reporting
	## warnings in reporter.log. If set to true, errors in
	## input lines will be handled as fatal errors for the
	## reader thread; reading will abort immediately and
	## an error will be logged to reporter.log.
	## Individual readers can use a different value using
	## the $config table.
	## fail_on_invalid_lines = T was the default behavior
	## until Bro 2.6.
	const fail_on_invalid_lines = F &redef;

	## Fail on file read problems. If set to true, the ascii
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
	## fail_on_file_problem = T was the default behavior
	## until Bro 2.6.
	const fail_on_file_problem = F &redef;

	## On input streams with a pathless or relative-path source filename,
	## prefix the following path. This prefix can, but need not be, absolute.
	## The default is to leave any filenames unchanged. This prefix has no
	## effect if the source already is an absolute path.
	const path_prefix = "" &redef;
}
