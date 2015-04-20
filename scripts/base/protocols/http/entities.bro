##! Analysis and logging for MIME entities found in HTTP sessions.

@load base/frameworks/files
@load base/utils/strings
@load base/utils/files
@load ./main

module HTTP;

export {
	type Entity: record {
		## Filename for the entity if discovered from a header.
		filename: string &optional;
	};

	redef record Info += {
		## An ordered vector of file unique IDs.
		orig_fuids:      vector of string &log &optional;

		## An ordered vector of mime types.
		orig_mime_types: vector of string &log &optional;

		## An ordered vector of file unique IDs.
		resp_fuids:      vector of string &log &optional;

		## An ordered vector of mime types.
		resp_mime_types: vector of string &log &optional;

		## The current entity.
		current_entity:  Entity           &optional;
		## Current number of MIME entities in the HTTP request message
		## body.
		orig_mime_depth: count            &default=0;
		## Current number of MIME entities in the HTTP response message
		## body.
		resp_mime_depth: count            &default=0;
	};

	redef record fa_file += {
		http: HTTP::Info &optional;
	};
}

event http_begin_entity(c: connection, is_orig: bool) &priority=10
	{
	set_state(c, is_orig);

	if ( is_orig )
		++c$http$orig_mime_depth;
	else
		++c$http$resp_mime_depth;

	c$http$current_entity = Entity();
	}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=3
	{
	if ( name == "CONTENT-DISPOSITION" &&
	     /[fF][iI][lL][eE][nN][aA][mM][eE]/ in value )
		{
		c$http$current_entity$filename = extract_filename_from_content_disposition(value);
		}
	else if ( name == "CONTENT-TYPE" &&
	          /[nN][aA][mM][eE][:blank:]*=/ in value )
		{
		c$http$current_entity$filename = extract_filename_from_content_disposition(value);
		}
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=5
	{
	if ( f$source == "HTTP" && c?$http ) 
		{
		f$http = c$http;

		if ( c$http?$current_entity && c$http$current_entity?$filename )
			f$info$filename = c$http$current_entity$filename;

		if ( f$is_orig )
			{
			if ( ! c$http?$orig_fuids )
				c$http$orig_fuids = string_vec(f$id);
			else
				c$http$orig_fuids[|c$http$orig_fuids|] = f$id;
			}
		else
			{
			if ( ! c$http?$resp_fuids )
				c$http$resp_fuids = string_vec(f$id);
			else
				c$http$resp_fuids[|c$http$resp_fuids|] = f$id;
			}
		}
	}

event file_sniff(f: fa_file, meta: fa_metadata) &priority=5
	{
	if ( ! f?$http || ! f?$is_orig )
		return;

	if ( ! meta?$mime_type )
		return;

	if ( f$is_orig )
		{
		if ( ! f$http?$orig_mime_types )
			f$http$orig_mime_types = string_vec(meta$mime_type);
		else
			f$http$orig_mime_types[|f$http$orig_mime_types|] = meta$mime_type;
		}
	else
		{
		if ( ! f$http?$resp_mime_types )
			f$http$resp_mime_types = string_vec(meta$mime_type);
		else
			f$http$resp_mime_types[|f$http$resp_mime_types|] = meta$mime_type;
		}
	}

event http_end_entity(c: connection, is_orig: bool) &priority=5
	{
	if ( c?$http && c$http?$current_entity ) 
		delete c$http$current_entity;
	}
