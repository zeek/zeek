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
	local parts = split_all(input, dir_pattern);

	if ( |parts| < 3 )
		return "";

	return parts[2];
	}

## Compresses a given path by removing '..'s and the parent directory it
## references and also removing dual '/'s and extraneous '/./'s.
##
## dir: a path string, either relative or absolute.
##
## Returns: a compressed version of the input path.
function compress_path(dir: string): string
	{
	const cdup_sep = /((\/)*([^\/]|\\\/)+)?((\/)+\.\.(\/)*)/;

	local parts = split_n(dir, cdup_sep, T, 1);
	if ( |parts| > 1 )
		{
		# reaching a point with two parent dir references back-to-back means
		# we don't know about anything higher in the tree to pop off
		if ( parts[2] == "../.." )
			return cat_string_array(parts);
		if ( sub_bytes(parts[2], 0, 1) == "/" )
			parts[2] = "/";
		else
			parts[2] = "";
		dir = cat_string_array(parts);
		return compress_path(dir);
		}

	const multislash_sep = /(\/\.?){2,}/;
	parts = split_all(dir, multislash_sep);
	for ( i in parts )
		if ( i % 2 == 0 )
			parts[i] = "/";
	dir = cat_string_array(parts);

	# remove trailing slashes from path
	if ( |dir| > 1 && sub_bytes(dir, |dir|, 1) == "/" )
		dir = sub_bytes(dir, 0, |dir| - 1);

	return dir;
	}

## Constructs a path to a file given a directory and a file name.
##
## dir: the directory in which the file lives.
##
## file_name: the name of the file.
##
## Returns: the concatenation of the directory path and file name, or just
##          the file name if it's already an absolute path.
function build_path(dir: string, file_name: string): string
	{
	return (file_name == absolute_path_pat) ?
		file_name : cat(dir, "/", file_name);
	}

## Returns a compressed path to a file given a directory and file name.
## See :bro:id:`build_path` and :bro:id:`compress_path`.
function build_path_compressed(dir: string, file_name: string): string
	{
	return compress_path(build_path(dir, file_name));
	}
