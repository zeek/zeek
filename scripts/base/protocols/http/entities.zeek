##! Analysis and logging for MIME entities found in HTTP sessions.

@load base/frameworks/files
@load base/frameworks/notice/weird
@load base/utils/strings
@load base/utils/files
@load ./main

module HTTP;

export {
	type Entity: record {
		## Filename for the entity if discovered from a header.
		filename: string &optional;
	};

	## Maximum number of originator files to log.
	## :zeek:see:`HTTP::max_files_policy` even is called once this
	## limit is reached to determine if it's enforced.
	option max_files_orig = 15;

	## Maximum number of responder files to log.
	## :zeek:see:`HTTP::max_files_policy` even is called once this
	## limit is reached to determine if it's enforced.
	option max_files_resp = 15;

	## Called when reaching the max number of files across a given HTTP
	## connection according to :zeek:see:`HTTP::max_files_orig`
	## or :zeek:see:`HTTP::max_files_resp`.  Break from the hook
	## early to signal that the file limit should not be applied.
	global max_files_policy: hook(f: fa_file, is_orig: bool);

	redef record Info += {
		## An ordered vector of file unique IDs.
		## Limited to :zeek:see:`HTTP::max_files_orig` entries.
		orig_fuids:      vector of string &log &optional;

		## An ordered vector of filenames from the client.
		## Limited to :zeek:see:`HTTP::max_files_orig` entries.
		orig_filenames:  vector of string &log &optional;

		## An ordered vector of mime types.
		## Limited to :zeek:see:`HTTP::max_files_orig` entries.
		orig_mime_types: vector of string &log &optional;

		## An ordered vector of file unique IDs.
		## Limited to :zeek:see:`HTTP::max_files_resp` entries.
		resp_fuids:      vector of string &log &optional;

		## An ordered vector of filenames from the server.
		## Limited to :zeek:see:`HTTP::max_files_resp` entries.
		resp_filenames:  vector of string &log &optional;

		## An ordered vector of mime types.
		## Limited to :zeek:see:`HTTP::max_files_resp` entries.
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
	if ( ! c$http?$current_entity )
		{
		local weird = Weird::Info(
			$ts=network_time(),
			$name="missing_HTTP_entity",
			$uid=c$uid,
			$id=c$id,
			$source="HTTP"
		);
		Weird::weird(weird);
		return;
		}

	if ( name == "CONTENT-DISPOSITION" &&
	     /[fF][iI][lL][eE][nN][aA][mM][eE][[:blank:]]*\*?=/ in value )
		{
		c$http$current_entity$filename = extract_filename_from_content_disposition(value);
		}
	else if ( name == "CONTENT-TYPE" &&
	          /[nN][aA][mM][eE][[:blank:]]*=/ in value )
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

		local size: count;
		local max: count;

		if ( f$is_orig )
			{
			size = f$http?$orig_fuids ? |f$http$orig_fuids| : 0;
			max = max_files_orig;
			}
		else
			{
			size = f$http?$resp_fuids ? |f$http$resp_fuids| : 0;
			max = max_files_resp;
			}

		if ( size >= max && hook HTTP::max_files_policy(f, f$is_orig) )
			return;

		if ( f$is_orig )
			{
			if ( ! c$http?$orig_fuids )
				c$http$orig_fuids = string_vec(f$id);
			else
				c$http$orig_fuids += f$id;

			if ( f$info?$filename )
				{
				if ( ! c$http?$orig_filenames )
					c$http$orig_filenames = string_vec(f$info$filename);
				else
					c$http$orig_filenames += f$info$filename;
				}
			}

		else
			{
			if ( ! c$http?$resp_fuids )
				c$http$resp_fuids = string_vec(f$id);
			else
				c$http$resp_fuids += f$id;

			if ( f$info?$filename )
				{
				if ( ! c$http?$resp_filenames )
					c$http$resp_filenames = string_vec(f$info$filename);
				else
					c$http$resp_filenames += f$info$filename;
				}

			}
		}
	}

event file_sniff(f: fa_file, meta: fa_metadata) &priority=5
	{
	if ( ! f?$http || ! f?$is_orig )
		return;

	if ( ! meta?$mime_type )
		return;

	local size: count;
	local max: count;

	if ( f$is_orig )
		{
		size = f$http?$orig_mime_types ? |f$http$orig_mime_types| : 0;
		max = max_files_orig;
		}
	else
		{
		size = f$http?$resp_mime_types ? |f$http$resp_mime_types| : 0;
		max = max_files_resp;
		}

	if ( size >= max && hook HTTP::max_files_policy(f, f$is_orig) )
		return;

	if ( f$is_orig )
		{
		if ( ! f$http?$orig_mime_types )
			f$http$orig_mime_types = string_vec(meta$mime_type);
		else
			f$http$orig_mime_types += meta$mime_type;
		}
	else
		{
		if ( ! f$http?$resp_mime_types )
			f$http$resp_mime_types = string_vec(meta$mime_type);
		else
			f$http$resp_mime_types += meta$mime_type;
		}
	}

event http_end_entity(c: connection, is_orig: bool) &priority=5
	{
	if ( c?$http && c$http?$current_entity )
		delete c$http$current_entity;
	}
