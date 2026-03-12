# This is just an excerpt from Zeek's policy script, detect-MHR.
# It has some slight modifications.

# The file_hash event is triggered each time Zeek sees file contents.
event file_hash(f: fa_file, kind: string, hash: string)
	{
	# Ensure this is a SHA1 hash and the file hash is one we care about.
	# (match_file_types is a configuration option defined elsewhere)
	if ( kind == "sha1" && match_file_types in f$info$mime_type )
		# If it matches, we enter the lookup function.
		do_mhr_lookup(hash, Notice::create_file_info(f));
	}
