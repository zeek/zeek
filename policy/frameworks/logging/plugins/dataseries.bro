##! Interface for the dataseries log writer.

module LogDataSeries;

export {
    ## Compression to use with the DS output file.  Options are:
	## 'none' -- No compression.
	## 'lzf' -- LZF compression.  Very quick, but leads to larger output files
	## 'lzo' -- LZO compression.  Very fast decompression times
	## 'gz' -- GZIP compression.  Slower than LZF, but also produces smaller output
	## 'bz2' -- BZIP2 compression.  Slower than GZIP, but also produces smaller output
	const ds_compression = "lzf" &redef;

    ## Extent buffer size.  Output is written in blocks of rows.
	## TODO: Tweak this value.
	const ds_extent_rows = 65536 &redef;

	## Should we dump the XML schema we use for this ds file to disk?
	## If yes, the XML schema shares the name of the logfile, but has
	## an XML ending.
	const ds_dump_schema = T &redef;
}

