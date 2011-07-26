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

    ## Extent buffer size.
	## Larger values here lead to better compression and more efficient writes, but
	## also increases the lag between the time events are received and the time they
	## are actually written to disk.
	const ds_extent_size = 65536 &redef;

	## Should we dump the XML schema we use for this ds file to disk?
	## If yes, the XML schema shares the name of the logfile, but has
	## an XML ending.
	const ds_dump_schema = T &redef;

	## How many threads should DataSeries spawn to perform compression?
	## Note that this dictates the number of threads per log stream.  If
	## you're using a lot of streams, you may want to keep this number
	## relatively small.
	##
	## Default value is 0, which will spawn one thread / core / stream
	## 
	## MAX is 128, MIN is 1
	const ds_num_threads = 1 &redef;

	## Should time be stored as an integer or a double?
	## Storing time as a double leads to possible precision issues and
	## could (significantly) increase the size of the resulting DS log.
	## That said, timestamps stored in double form are more consistent
	## with the rest of bro and are more easily readable / understandable
	## when working with the raw DataSeries format.
	## 
	## Integer timestamps are used by default.
	const ds_use_integer = T &redef;
}

