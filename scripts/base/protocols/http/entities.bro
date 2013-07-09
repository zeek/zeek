##! Analysis and logging for MIME entities found in HTTP sessions.

@load base/frameworks/files
@load base/utils/strings
@load base/utils/files
@load ./main

module HTTP;

export {
	type Entity: record {
		## Depth of the entity if multiple entities are sent in a single transaction.
		depth: count &default=0;

		## Filename for the entity if discovered from a header.
		filename: string &optional;
	};

	redef record Info += {
		## The current entity being seen.
		entity:          Entity    &optional;

		## Current number of MIME entities in the HTTP request message body.
		orig_mime_depth: count     &default=0;
		## Current number of MIME entities in the HTTP response message body.
		resp_mime_depth: count     &default=0;
	};
}

event http_begin_entity(c: connection, is_orig: bool) &priority=10
	{
	set_state(c, F, is_orig);

	if ( is_orig )
		++c$http$orig_mime_depth;
	else
		++c$http$resp_mime_depth;

	c$http$entity = Entity($depth = is_orig ? c$http$orig_mime_depth : c$http$resp_mime_depth);
	}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=3
	{
	if ( name == "CONTENT-DISPOSITION" &&
	     /[fF][iI][lL][eE][nN][aA][mM][eE]/ in value )
		{
		c$http$entity$filename = extract_filename_from_content_disposition(value);
		}
	else if ( name == "CONTENT-TYPE" &&
	          /[nN][aA][mM][eE][:blank:]*=/ in value )
		{
		c$http$entity$filename = extract_filename_from_content_disposition(value);
		}
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=5
	{
	if ( f$source == "HTTP" && c$http?$entity ) 
		{
		f$info$depth = c$http$entity$depth;
		if ( c$http$entity?$filename )
			f$info$filename = c$http$entity$filename;
		}
	}

event http_end_entity(c: connection, is_orig: bool) &priority=5
	{
	if ( c?$http && c$http?$entity ) 
		delete c$http$entity;
	}
