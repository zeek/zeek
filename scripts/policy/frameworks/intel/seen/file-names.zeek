@load base/frameworks/intel
@load ./where-locations

event file_new(f: fa_file)
	{
	# If there are connections attached, we'll be using
	# file_over_new_connection() for reporting the
	# filename instead as it's more likely to be populated.
	if ( f?$conns && |f$conns| > 0 )
		return;

	if ( f?$info && f$info?$filename )
		Intel::seen([$indicator=f$info$filename,
		             $indicator_type=Intel::FILE_NAME,
		             $f=f,
		             $where=Files::IN_NAME]);
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=-5
	{
        # Skip SMB, there's a custom implementation in smb-filenames.zeek
        if ( f$source == "SMB" )
            return;

	if ( f?$info && f$info?$filename )
		Intel::seen([$indicator=f$info$filename,
		             $indicator_type=Intel::FILE_NAME,
		             $f=f,
		             $where=Files::IN_NAME]);
	}
