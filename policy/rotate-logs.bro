# $Id: rotate-logs.bro 4685 2007-07-30 23:50:26Z vern $

module RotateLogs;

export {
	# Maps file names to postprocessors.
	global postprocessors: table[string] of string &redef;

	# Default postprocessor.
	global default_postprocessor = "" &redef;

	# Files which are to be rotated according to log_rotate_interval
	# and log_max_size, but aren't represented by a file object.
	global aux_files: set[string] &redef;

	# For aux_files, the time interval in which we check the files' sizes.
	global aux_check_size_interval = 30 secs &redef;

	# Callback to provide name for rotated file.
	global build_name: function(info: rotate_info): string &redef;

	# Default naming suffix format.
	global date_format = "%y-%m-%d_%H.%M.%S" &redef;

	# Whether to rotate files when shutting down.
	global rotate_on_shutdown = T &redef;

	# If set, postprocessors get this tag as an additional argument.
	global tag = "" &redef;
}

# Default rotation is once per hour.
redef log_rotate_interval = 1 hr;

# There are other variables that are defined in bro.init.  Here are
# some example of how these might be redefined.
# redef log_rotate_base_time = "0:00";
# redef log_max_size = 1e7;
# redef log_encryption_key = "mybigsecret";

# Given a rotate info record, returns new rotated filename.
function build_name(info: rotate_info): string
	{
	return fmt("%s-%s", info$old_name, strftime(date_format, info$open));
	}

# Run post-processor on file. If there isn't any postprocessor defined,
# we move the file to a nicer name.
function run_pp(info: rotate_info)
	{
	local pp = default_postprocessor;

	if ( info$old_name in postprocessors )
		pp = postprocessors[info$old_name];

	if ( pp != "" )
		# The date format is hard-coded here to provide a standardized
		# script interface.
		system(fmt("%s %s %s %s %s %s",
				pp, info$new_name, info$old_name,
				strftime("%y-%m-%d_%H.%M.%S", info$open),
				strftime("%y-%m-%d_%H.%M.%S", info$close),
				tag));
	else
		system(fmt("/bin/mv %s %s %s",
				info$new_name, build_name(info), tag));
	}

# Rotate file.
function rotate(f: file)
	{
	local info = rotate_file(f);
	if ( info$old_name == "" )
		# Error.
		return;

	run_pp(info);
	}

# Rotate file, but only if we know the name.
function rotate_by_name(f: string)
	{
	local info = rotate_file_by_name(f);
	if ( info$old_name == "" )
		# Error.
		return;

	run_pp(info);
	}

function make_nice_timestamp(i: interval) : time
	{
	# To get nice timestamps, we round the time up to
	# the next multiple of the rotation interval.

	local nt = time_to_double(network_time());
	local ri = interval_to_double(i);

	return double_to_time(floor(nt / ri) * ri + ri);
	}

# Raised when a &rotate_interval expires.
event rotate_interval(f: file)
	{
	if ( bro_is_terminating() && ! rotate_on_shutdown )
		return;

	rotate(f);
	}

# Raised when a &rotate_size is reached.
event rotate_size(f: file)
	{
	rotate(f);
	}

# Raised for aux_files when log_rotate_inverval expires.

global first_aux_rotate_interval = T;

event aux_rotate_interval()
	{
	if ( bro_is_terminating() && ! rotate_on_shutdown )
		return;

	if ( ! first_aux_rotate_interval )
		for ( f in aux_files )
			rotate_by_name(f);

	first_aux_rotate_interval = F;

	if ( ! bro_is_terminating() )
		schedule calc_next_rotate(log_rotate_interval)
			{ aux_rotate_interval() };
	}

# Regularly raised to check aux_files' sizes.
event aux_check_size()
	{
	for ( f in aux_files )
		if ( file_size(f) > log_max_size )
			rotate_by_name(f);

	if ( ! bro_is_terminating() )
		schedule aux_check_size_interval { aux_check_size() };
	}

event bro_init()
	{
	if ( length(aux_files) != 0 )
		{
		if ( log_rotate_interval != 0 secs )
			schedule calc_next_rotate(log_rotate_interval)
				{ aux_rotate_interval() };

		if ( log_max_size != 0 )
			schedule aux_check_size_interval { aux_check_size() };
		}
	}
