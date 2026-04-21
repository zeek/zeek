##! Types used by the Zip file analyzer plugin

module ZIP;

export {
	## Compression methods used by Zip. Only the methods that Zeek supports for
	## content analysis are defined.
	type CompressionMethod: enum {
		Uncompressed = 0,
		Deflate = 8,
	};
}
