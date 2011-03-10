
module LogAscii;

export {
	# Output everything to stdout rather than into files. This is primarily
	# for testing purposes.
	const output_to_stdout = F &redef;

	# True to include a header line with column names.
	const include_header = T &redef;

	# The prefix for the header line if included.
	const header_prefix = "# " &redef;

	# The separator between fields.
	const separator = "\t" &redef;

	# The string to use for empty string fields.
	const empty_field = "" &redef;

	# The string to use for an unset optional field.
	const unset_field = "-" &redef;
}


