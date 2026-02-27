zeek-cut
========

The "zeek-cut" utility reads ASCII Zeek logs on standard input
and outputs them to standard output with only the specified columns (the
column names can be found in each log file in the "#fields" header line).
If no column names are specified, then "zeek-cut" simply outputs all columns.

There are several command-line options available to modify the output (run
"zeek-cut -h" to see a list of all options).  There are options to convert
timestamps into human-readable format, and options to specify whether or not
to include the format header lines in the output (by default, they're not
included).

For example, the following command will output the three specified columns
from conn.log with the timestamps from the "ts" column being converted to
human-readable format::

    cat conn.log | zeek-cut -d ts id.orig_h id.orig_p

The specified order of the column names determines the output order of the
columns (i.e., "zeek-cut" can reorder the columns).

The "zeek-cut" utility can read the concatenation of one or more uncompressed
ASCII log files (however, JSON format is not supported) produced by Zeek
version 2.0 or newer, as long as each log file contains format header
lines (these are the lines at the beginning of the file starting with "#").
In fact, "zeek-cut" can process the concatenation of multiple ASCII log files
that have different column layouts.

To read a compressed log file, a tool such as "zcat" must be used to
uncompress the file.  For example, "zeek-cut" can read a group of compressed
conn.log files with a command like this::

    zcat conn.*.log.gz | zeek-cut
