##! Analysis and logging for MIME entities found in SMTP sessions.

@load base/utils/strings
@load base/utils/files
@load ./main

module SMTP;

export {
	redef enum Notice::Type += {
		## Indicates that an MD5 sum was calculated for a MIME message.
		MD5,
	};

	redef enum Log::ID += { ENTITIES_LOG };

	type EntityInfo: record {
		## This is the timestamp of when the MIME content transfer began.
		ts:               time    &log;
		uid:              string  &log;
		id:               conn_id &log;
		## A count to represent the depth of this message transaction in a 
		## single connection where multiple messages were transferred.
		trans_depth:      count  &log;
		## The filename seen in the Content-Disposition header.
		filename:         string  &log &optional;
		## Track how many bytes of the MIME encoded file have been seen.
		content_len:      count   &log &default=0;
		## The mime type of the entity discovered through magic bytes identification.
		mime_type:        string  &log &optional;
		
		## The calculated MD5 sum for the MIME entity.
		md5:              string  &log &optional;
		## Optionally calculate the file's MD5 sum.  Must be set prior to the 
		## first data chunk being see in an event.
		calc_md5:         bool    &default=F;
		## This boolean value indicates if an MD5 sum is being calculated 
		## for the current file transfer.
		calculating_md5:  bool    &default=F;
		
		## Optionally write the file to disk.  Must be set prior to first 
		## data chunk being seen in an event.
		extract_file:     bool    &default=F;
		## Store the file handle here for the file currently being extracted.
		extraction_file:  file    &log &optional;
	};

	redef record Info += {
		## The in-progress entity information.
		current_entity:   EntityInfo &optional;
	};

	redef record State += {
		## Store a count of the number of files that have been transferred in
		## a conversation to create unique file names on disk.
		num_extracted_files:  count   &default=0;
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

# This has priority -10 because other handlers need to know the current
# content_len before it's updated by this handler.
event mime_segment_data(c: connection, length: count, data: string) &priority=-10
	{
	if ( ! c?$smtp ) return;
	
	c$smtp$current_entity$content_len = c$smtp$current_entity$content_len + length;
	}

event mime_segment_data(c: connection, length: count, data: string) &priority=7
    {
	if ( ! c?$smtp ) return;
	if ( c$smtp$current_entity$content_len == 0 )
		c$smtp$current_entity$mime_type = split1(identify_data(data, T), /;/)[1];
	}

event mime_segment_data(c: connection, length: count, data: string) &priority=-5
	{
	if ( ! c?$smtp ) return;

	if ( c$smtp$current_entity$content_len == 0 )
		{
		if ( generate_md5 in c$smtp$current_entity$mime_type && ! never_calc_md5 )
			c$smtp$current_entity$calc_md5 = T;

		if ( c$smtp$current_entity$calc_md5 )
			{
			c$smtp$current_entity$calculating_md5 = T;
			md5_hash_init(c$id);
			}
		}

	if ( c$smtp$current_entity$calculating_md5 )
		md5_hash_update(c$id, data);
}

## In the event of a content gap during the MIME transfer, detect the state for
## the MD5 sum calculation and stop calculating the MD5 since it would be
## incorrect anyway.
event content_gap(c: connection, is_orig: bool, seq: count, length: count) &priority=5
	{
	if ( is_orig || ! c?$smtp || ! c$smtp?$current_entity ) return;

	if ( c$smtp$current_entity$calculating_md5 )
		{
		c$smtp$current_entity$calculating_md5 = F;
		md5_hash_finish(c$id);
		}
	}

event mime_end_entity(c: connection) &priority=-3
    {
	# TODO: this check is only due to a bug in mime_end_entity that
	#       causes the event to be generated twice for the same real event.
	if ( ! c?$smtp || ! c$smtp?$current_entity )
		return;

	if ( c$smtp$current_entity$calculating_md5 )
		{
		c$smtp$current_entity$md5 = md5_hash_finish(c$id);

		NOTICE([$note=MD5, $msg=fmt("Calculated a hash for a MIME entity from %s", c$id$orig_h),
				$sub=c$smtp$current_entity$md5, $conn=c]);
		}
	}

event mime_one_header(c: connection, h: mime_header_rec)
	{
	if ( ! c?$smtp ) return;
	
	if ( h$name == "CONTENT-DISPOSITION" &&
	     /[fF][iI][lL][eE][nN][aA][mM][eE]/ in h$value )
		c$smtp$current_entity$filename = extract_filename_from_content_disposition(h$value);
	}

event mime_end_entity(c: connection) &priority=-5
	{
	if ( ! c?$smtp ) return;

	# This check and the delete below are just to cope with a bug where
	# mime_end_entity can be generated multiple times for the same event.
	if ( ! c$smtp?$current_entity )
		return;

	# Only log is there was some content.
	if ( c$smtp$current_entity$content_len > 0 )
		Log::write(SMTP::ENTITIES_LOG, c$smtp$current_entity);

	delete c$smtp$current_entity;
	}

event mime_segment_data(c: connection, length: count, data: string) &priority=5
	{
	if ( ! c?$smtp ) return;
	
	if ( extract_file_types in c$smtp$current_entity$mime_type )
		c$smtp$current_entity$extract_file = T;
	}

event mime_segment_data(c: connection, length: count, data: string) &priority=3
	{
	if ( ! c?$smtp ) return;
	
	if ( c$smtp$current_entity$extract_file && 
	     c$smtp$current_entity$content_len == 0 )
		{
		local suffix = fmt("%d.dat", ++c$smtp_state$num_extracted_files);
		local fname = generate_extraction_filename(extraction_prefix, c, suffix);
		c$smtp$current_entity$extraction_file = open(fname);
		enable_raw_output(c$smtp$current_entity$extraction_file);
		}
	}

event mime_segment_data(c: connection, length: count, data: string) &priority=-5
	{
	if ( ! c?$smtp ) return;
	
	if ( c$smtp$current_entity$extract_file && c$smtp$current_entity?$extraction_file )
		print c$smtp$current_entity$extraction_file, data;
	}

event mime_end_entity(c: connection) &priority=-3
	{
	if ( ! c?$smtp ) return;
	
	# TODO: this check is only due to a bug in mime_end_entity that
	#       causes the event to be generated twice for the same real event.
	if ( ! c$smtp?$current_entity )
		return;

	if ( c$smtp$current_entity?$extraction_file )
		close(c$smtp$current_entity$extraction_file);
	}
