
module LogAscii;

export {
	# Output everything to stdout rather than into files. This is primarily
	# for testing purposes.
	const output_to_stdout = F &redef;

	# The separator between fields.
	const separator = "\t" &redef;

	# True to include a header line with column names.
	const include_header = T &redef;
}

