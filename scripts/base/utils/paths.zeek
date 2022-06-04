##! Functions to parse and manipulate UNIX style paths and directories.

const absolute_path_pat = /(\/|[A-Za-z]:[\\\/]).*/;

## Given an arbitrary string, extracts a single, absolute path (directory
## with filename).
##
## .. todo:: Make this work on Window's style directories.
##
## input: a string that may contain an absolute path.
##
## Returns: the first absolute path found in input string, else an empty string.
function extract_path(input: string): string
	{
	const dir_pattern = /(\/|[A-Za-z]:[\\\/])([^\"\ ]|(\\\ ))*/;
	local parts = split_string_all(input, dir_pattern);

	if ( |parts| < 3 )
		return "";

	return parts[1];
	}

## Constructs a path to a file given a directory and a file name.
##
## dir: the directory in which the file lives.
##
## file_name: the name of the file.
##
## Returns: the concatenation of the directory path and file name, or just
##          the file name if it's already an absolute path or dir is empty.
function build_path(dir: string, file_name: string): string
	{
	# Avoid introducing "//" into the result:
	local sep = ends_with(dir, "/") ? "" : "/";
	return (file_name == absolute_path_pat || dir == "") ?
		file_name : cat(dir, sep, file_name);
	}

## Returns a compressed path to a file given a directory and file name.
## See :zeek:id:`build_path` and :zeek:id:`compress_path`.
function build_path_compressed(dir: string, file_name: string): string
	{
	return compress_path(build_path(dir, file_name));
	}
