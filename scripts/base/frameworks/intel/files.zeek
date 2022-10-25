##! File analysis framework integration for the intelligence framework. This
##! script manages file information in intelligence framework data structures.

@load ./main

module Intel;

export {
	## Enum type to represent various types of intelligence data.
	redef enum Type += {
		## File hash which is non-hash type specific.  It's up to the
		## user to query for any relevant hash types.
		FILE_HASH,
		## File name.  Typically with protocols with definite
		## indications of a file name.
		FILE_NAME,
	};

	## Information about a piece of "seen" data.
	redef record Seen += {
		## If the data was discovered within a file, the file record
		## should go here to provide context to the data.
		f:              fa_file  &optional;
		## If the data was discovered within a file, the file uid should
		## go here to provide context to the data. If the file record *f*
		## is provided, this will be automatically filled out.
		fuid:           string   &optional;
	};

	## Record used for the logging framework representing a positive
	## hit within the intelligence framework.
	redef record Info += {
		## If a file was associated with this intelligence hit,
		## this is the uid for the file.
		fuid:           string   &log &optional;
		## A mime type if the intelligence hit is related to a file.
		## If the $f field is provided this will be automatically filled
		## out.
		file_mime_type: string   &log &optional;
		## Frequently files can be "described" to give a bit more context.
		## If the $f field is provided this field will be automatically
		## filled out.
		file_desc:      string   &log &optional;
	};
}

# Add file information to matches if available.
hook extend_match(info: Info, s: Seen, items: set[Item]) &priority=6
	{
	if ( s?$f )
		{
		s$fuid = s$f$id;

		if ( s$f?$conns && |s$f$conns| == 1 )
			{
			for ( _, c in s$f$conns )
				s$conn = c;
			}

		if ( ! info?$file_mime_type && s$f?$info && s$f$info?$mime_type )
			info$file_mime_type = s$f$info$mime_type;

		if ( ! info?$file_desc )
			info$file_desc = Files::describe(s$f);
		}

	if ( s?$fuid )
		info$fuid = s$fuid;
	}
