##! Interface for the binary input reader.

module InputBinary;

export {
	## Size of data chunks to read from the input file at a time.
	const chunk_size = 1024 &redef;
}
