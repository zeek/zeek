@load base/frameworks/files

module SMB;

export {
	## Default file handle provider for SMB.
	global get_file_handle: function(c: connection, is_orig: bool): string;

	## Default file describer for SMB.
	global describe_file: function(f: fa_file): string;
}

function get_file_handle(c: connection, is_orig: bool): string
	{
	if ( ! (c$smb_state?$current_file &&
	        ((c$smb_state$current_file?$name && c$smb_state$current_file$name !in pipe_names) || 
	         c$smb_state$current_file?$path)) )
		{
		# TODO - figure out what are the cases where this happens.
		return "";
		}

	local current_file = c$smb_state$current_file;
	local path_name = current_file?$path ? current_file$path : "";
	local file_name = current_file?$name ? current_file$name : "";
	# Include last_mod time if available because if a file has been modified it
	# should be considered a new file.
	local last_mod  = current_file?$times ? current_file$times$modified : double_to_time(0.0);
	return cat(Analyzer::ANALYZER_SMB, c$id$orig_h, c$id$resp_h, path_name, file_name, last_mod);
	}

function describe_file(f: fa_file): string
	{
	# This shouldn't be needed, but just in case...
	if ( f$source != "SMB" )
		return "";

	for ( cid in f$conns )
		{
		local info = f$conns[cid];
		if ( info?$smb_state && info$smb_state?$current_file && info$smb_state$current_file?$name )
			return info$smb_state$current_file$name;
		}
	return "";
	}

event bro_init() &priority=5
	{
	Files::register_protocol(Analyzer::ANALYZER_SMB,
	                         [$get_file_handle = SMB::get_file_handle,
	                          $describe        = SMB::describe_file]);
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=5
	{
	if ( c?$smb_state && c$smb_state?$current_file )
		{
		c$smb_state$current_file$fuid = f$id;

		if ( c$smb_state$current_file?$name )
			f$info$filename = c$smb_state$current_file$name;
		}
	}
