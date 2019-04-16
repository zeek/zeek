##! Interface for the binary input reader.

module InputBinary;

export {
	## Size of data chunks to read from the input file at a time.
	const chunk_size = 1024 &redef;

	## On input streams with a pathless or relative-path source filename,
	## prefix the following path. This prefix can, but need not be, absolute.
	## The default is to leave any filenames unchanged. This prefix has no
	## effect if the source already is an absolute path.
	const path_prefix = "" &redef;
}
