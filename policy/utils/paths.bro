##! Functions to parse and manipulate UNIX style paths and directories.

const absolute_path_pat = /(\/|[A-Za-z]:[\\\/]).*/;

## Given an arbitrary string, this should extract a single directory with
## filename if it's included.
## TODO: Make this work on Window's style directories.
function extract_directory(input: string): string
	{
	const dir_pattern = /\"([^\"]|\"\")*(\/|\\)([^\"]|\"\")*\"/;
	local parts = split_all(input, dir_pattern);

	# This basically indicates no identifiable directory was found.
	if ( |parts| < 3 )
		return "";

	local d = parts[2];
	return sub_bytes(d, 2, int_to_count(|d| - 2));
	}

## Process ..'s and eliminate duplicate '/'s
function compress_path(dir: string): string
	{
	const cdup_sep = /((\/)+([^\/]|\\\/)+)?((\/)+\.\.(\/)+)/;

	local parts = split_n(dir, cdup_sep, T, 1);
	if ( length(parts) > 1 )
		{
		parts[2] = "/";
		dir = cat_string_array(parts);
		return compress_path(dir);
		}

	const multislash_sep = /(\/){2,}/;
	parts = split_all(dir, multislash_sep);
	for ( i in parts )
		if ( i % 2 == 0 )
			parts[i] = "/";
	dir = cat_string_array(parts);

	return dir;
	}

## Computes the absolute path with current working directory.
function absolute_path(cwd: string, file_name: string): string
	{
	local abs_file_name: string;
	if ( file_name == absolute_path_pat ) # start with '/' or 'A:\'
		abs_file_name = file_name;
	else
		abs_file_name = string_cat(cwd, "/", file_name);
	return compress_path(abs_file_name);
	}

## Takes a directory and a filename and combines them together into a full
## filename with path.
function build_full_path(cwd: string, file_name: string): string
	{
	return (file_name == absolute_path_pat) ?
		file_name : cat(cwd, "/", file_name);
	}
