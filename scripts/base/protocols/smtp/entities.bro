##! Analysis and logging for MIME entities found in SMTP sessions.

@load base/utils/strings
@load base/utils/files
@load ./main

module SMTP;

export {
	redef enum Log::ID += { ENTITIES_LOG };

	type EntityInfo: record {
		## This is the timestamp of when the MIME content transfer began.
		ts:               time            &log;
		uid:              string          &log;
		id:               conn_id         &log;
		## A count to represent the depth of this message transaction in a 
		## single connection where multiple messages were transferred.
		trans_depth:      count           &log;
		## The filename seen in the Content-Disposition header.
		filename:         string          &log &optional;
		## Track how many bytes of the MIME encoded file have been seen.
		content_len:      count           &log &default=0;
		## The mime type of the entity discovered through magic bytes identification.
		mime_type:        string          &log &optional;
		
		## The calculated MD5 sum for the MIME entity.
		md5:              string          &log &optional;
		## Optionally calculate the file's MD5 sum.  Must be set prior to the 
		## first data chunk being see in an event.
		calc_md5:         bool            &default=F;
		
		## Optionally write the file to disk.  Must be set prior to first 
		## data chunk being seen in an event.
		extract_file:     bool            &default=F;
		## Store the file handle here for the file currently being extracted.
		extraction_file:  string          &log &optional;
	};

	redef record Info += {
		## The in-progress entity information.
		current_entity:   EntityInfo &optional;
	};

	redef record State += {
		## Track the number of MIME encoded files transferred during a session.
		mime_level:           count   &default=0;
	};

	## Generate MD5 sums for these filetypes.
	const generate_md5 = /application\/x-dosexec/    # Windows and DOS executables
	                   | /application\/x-executable/ # *NIX executable binary
	                   &redef;

	## Pattern of file mime types to extract from MIME bodies.
	const extract_file_types = /NO_DEFAULT/ &redef;

	## The on-disk prefix for files to be extracted from MIME entity bodies.
	const extraction_prefix = "smtp-entity" &redef;

	## If set, never generate MD5s. This is mainly for testing purposes to create
	## reproducable output in the case that the decision whether to create
	## checksums depends on environment specifics.
	const never_calc_md5 = F &redef;

	global log_mime: event(rec: EntityInfo);
}

global extract_count: count = 0;

event bro_init() &priority=5
	{
	Log::create_stream(SMTP::ENTITIES_LOG, [$columns=EntityInfo, $ev=log_mime]);
	}

function set_session(c: connection, new_entity: bool)
	{
	if ( ! c$smtp?$current_entity || new_entity )
		{
		local info: EntityInfo;
		info$ts=network_time();
		info$uid=c$uid;
		info$id=c$id;
		info$trans_depth=c$smtp$trans_depth;
		
		c$smtp$current_entity = info;
		++c$smtp_state$mime_level;
		}
	}

event mime_begin_entity(c: connection) &priority=10
	{
	if ( ! c?$smtp ) return;

	set_session(c, T);
	}

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	&priority=5
	{
	if ( trig != FileAnalysis::TRIGGER_NEW ) return;
	if ( ! info?$source ) return;
	if ( info$source != "SMTP" ) return;
	if ( ! info?$conns ) return;

	local fname: string = fmt("%s-%s-%d.dat", extraction_prefix, info$file_id,
	                          extract_count);
	local extracting: bool = F;

	for ( cid in info$conns )
		{
		local c: connection = info$conns[cid];

		if ( ! c?$smtp ) next;
		if ( ! c$smtp?$current_entity ) next;

		if ( c$smtp$current_entity$extract_file )
			{
			if ( ! extracting )
				{
				FileAnalysis::add_action(info$file_id,
				                         [$act=FileAnalysis::ACTION_EXTRACT,
				                          $extract_filename=fname]);
				extracting = T;
				++extract_count;
				}

			c$smtp$current_entity$extraction_file = fname;
			}

		if ( c$smtp$current_entity$calc_md5 )
			FileAnalysis::add_action(info$file_id,
			                         [$act=FileAnalysis::ACTION_MD5]);
		}
	}

function check_extract_by_type(info: FileAnalysis::Info)
	{
	if ( extract_file_types !in info$mime_type ) return;

	for ( act in info$actions )
		if ( act$act == FileAnalysis::ACTION_EXTRACT ) return;

	local fname: string = fmt("%s-%s-%d.dat", extraction_prefix, info$file_id,
	                          extract_count);
	++extract_count;
	FileAnalysis::add_action(info$file_id, [$act=FileAnalysis::ACTION_EXTRACT,
	                         $extract_filename=fname]);

	if ( ! info?$conns ) return;

	for ( cid in info$conns )
		{
		local c: connection = info$conns[cid];

		if ( ! c?$smtp ) next;

		c$smtp$current_entity$extraction_file = fname;
		}
	}

function check_md5_by_type(info: FileAnalysis::Info)
	{
	if ( never_calc_md5 ) return;
	if ( generate_md5 !in info$mime_type ) return;

	FileAnalysis::add_action(info$file_id, [$act=FileAnalysis::ACTION_MD5]);
	}

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	&priority=5
	{
	if ( trig != FileAnalysis::TRIGGER_TYPE ) return;
	if ( ! info?$mime_type ) return;
	if ( ! info?$source ) return;
	if ( info$source != "SMTP" ) return;

	if ( info?$conns )
		for ( cid in info$conns )
			{
			local c: connection = info$conns[cid];

			if ( ! c?$smtp ) next;
			if ( ! c$smtp?$current_entity ) next;

			c$smtp$current_entity$mime_type = info$mime_type;
			}

	check_extract_by_type(info);
	check_md5_by_type(info);
	}

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	&priority=5
	{
	if ( trig != FileAnalysis::TRIGGER_GAP ) return;
	if ( ! info?$source ) return;
	if ( info$source != "SMTP" ) return;
	if ( ! info?$conns ) return;

	for ( cid in info$conns )
		{
		local c: connection = info$conns[cid];

		if ( ! c?$smtp ) next;
		if ( ! c$smtp?$current_entity ) next;

		FileAnalysis::remove_action(info$file_id,
		                            [$act=FileAnalysis::ACTION_MD5]);
		}
	}

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	&priority=5
	{
	if ( trig != FileAnalysis::TRIGGER_EOF &&
	     trig != FileAnalysis::TRIGGER_DONE ) return;
	if ( ! info?$source ) return;
	if ( info$source != "SMTP" ) return;
	if ( ! info?$conns ) return;

	for ( cid in info$conns )
		{
		local c: connection = info$conns[cid];

		if ( ! c?$smtp ) next;
		if ( ! c$smtp?$current_entity ) next;
		# Only log is there was some content.
		if ( info$seen_bytes == 0 ) next;

		local act: FileAnalysis::ActionArgs = [$act=FileAnalysis::ACTION_MD5];

		if ( act in info$actions )
			{
			local result = info$actions[act];
			if ( result?$md5 )
				c$smtp$current_entity$md5 = result$md5;
			}

		c$smtp$current_entity$content_len = info$seen_bytes;

		Log::write(SMTP::ENTITIES_LOG, c$smtp$current_entity);
		delete c$smtp$current_entity;
		return;
		}
	}

event mime_one_header(c: connection, h: mime_header_rec)
	{
	if ( ! c?$smtp ) return;
	
	if ( h$name == "CONTENT-DISPOSITION" &&
	     /[fF][iI][lL][eE][nN][aA][mM][eE]/ in h$value )
		c$smtp$current_entity$filename = extract_filename_from_content_disposition(h$value);

	if ( h$name == "CONTENT-TYPE" &&
	     /[nN][aA][mM][eE][:blank:]*=/ in h$value )
		c$smtp$current_entity$filename = extract_filename_from_content_disposition(h$value);
	}
