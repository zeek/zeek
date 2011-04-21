##! Interface for the ascii log writer.

module LogAscii;

export {
	## If true, output everything to stdout rather than
	## into files. This is primarily for debugging purposes.
	const output_to_stdout = F &redef;

	## If true, include a header line with column names.
	const include_header = T &redef;

	# Prefix for the header line if included.
	const header_prefix = "# " &redef;

	## Separator between fields.
	const separator = "\t" &redef;

	## Separator between set elements.
	const set_separator = "," &redef;

	## String to use for empty fields.
	const empty_field = "" &redef;

	## String to use for an unset &optional field.
	const unset_field = "-" &redef;
}


