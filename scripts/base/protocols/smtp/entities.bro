##! Analysis and logging for MIME entities found in SMTP sessions.

@load base/frameworks/files
@load base/utils/strings
@load base/utils/files
@load ./main

module SMTP;

export {
	type Entity: record {
		## Filename for the entity if discovered from a header.
		filename: string &optional;
	};

	redef record Info += {
		## The current entity being seen.
		entity: Entity &optional;
	};

	redef record State += {
		## Track the number of MIME encoded files transferred
		## during a session.
		mime_depth: count &default=0;
	};
}

event mime_begin_entity(c: connection) &priority=10
	{
	if ( c?$smtp )
		c$smtp$entity = Entity();
	if ( c?$smtp_state )
		++c$smtp_state$mime_depth;
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=5
	{
	if ( f$source == "SMTP" && c?$smtp )
		{
		if ( c$smtp?$entity && c$smtp$entity?$filename )
			f$info$filename = c$smtp$entity$filename;
		f$info$depth = c$smtp_state$mime_depth;
		}
	}

event mime_one_header(c: connection, h: mime_header_rec) &priority=5
	{
	if ( ! c?$smtp )
		return;

	if ( h$name == "CONTENT-DISPOSITION" &&
	     /[fF][iI][lL][eE][nN][aA][mM][eE]/ in h$value )
		c$smtp$entity$filename = extract_filename_from_content_disposition(h$value);

	if ( h$name == "CONTENT-TYPE" &&
	     /[nN][aA][mM][eE][:blank:]*=/ in h$value )
		c$smtp$entity$filename = extract_filename_from_content_disposition(h$value);
	}

event mime_end_entity(c: connection) &priority=5
	{
	if ( c?$smtp && c$smtp?$entity )
		delete c$smtp$entity;
	}
