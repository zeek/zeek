##! Analysis and logging for MIME entities found in SMTP sessions.

@load utils/strings
@load utils/files
@load ./main

module SMTP;

export {
	redef enum Notice::Type += {
		## Indicates that an MD5 sum was calculated for a MIME message.
		MD5,
	};

	redef enum Log::ID += { SMTP_MIME };

	type MimeInfo: record {
		## This is the timestamp of when the MIME content transfer began.
		ts:               time    &log;
		uid:              string  &log;
		id:               conn_id &log;
		## The filename seen in the Content-Disposition header.
		filename:         string  &log &optional;
		## Track how many byte of the MIME encoded file have been seen.
		content_len:      count   &log &default=0;
		mime_type:        string  &log &optional;
		## The calculated MD5 sum for the MIME entity.
		md5:             string  &log &optional;
		## Optionally calculate the file's MD5 sum.  Must be set prior to the 
		## first data chunk being see in an event.
		calc_md5:        bool    &default=F;
		## This boolean value indicates if an MD5 sum is being calculated 
		## for the current file transfer.
		calculating_md5: bool    &default=F;
		## Optionally write the file to disk.  Must be set prior to first 
		## data chunk being seen in an event.
		extract_file:         bool    &default=F;
		## Store the file handle here for the file currently being extracted.
		extraction_file:      file    &log &optional;
	};

	type MimeState: record {
		## Store a count of the number of files that have been transferred in
		## this conversation to create unique file names on disk.
		num_extracted_files:  count   &default=0;
		## Track the number of MIME encoded files transferred during this session.
		level:            count   &default=0;
	};

	## Generate MD5 sums for these filetypes.
	const generate_md5 = /application\/x-dosexec/    # Windows and DOS executables
					   | /application\/x-executable/ # *NIX executable binary
					   &redef;

	## Pattern of file mime types to extract from MIME bodies.
	const extract_file_types = /NO_DEFAULT/ &redef;

	## The on-disk prefix for files to be extracted from MIME entity bodies.
	const extraction_prefix = "smtp-mime-item" &redef;

	global log_mime: event(rec: MimeInfo);
}

redef record connection += {
	smtp_mime:       MimeInfo &optional;
	smtp_mime_state: MimeState &optional;
};

event bro_init()
	{
	Log::create_stream(SMTP_MIME, [$columns=MimeInfo, $ev=log_mime]);
	}

function new_mime_session(c: connection): MimeInfo
	{
	local info: MimeInfo;

	info$ts=network_time();
	info$uid=c$uid;
	info$id=c$id;
	return info;
	}

function set_session(c: connection, new_entity: bool)
	{
	if ( ! c?$smtp_mime_state )
		c$smtp_mime_state = [];

	if ( ! c?$smtp_mime || new_entity )
		c$smtp_mime = new_mime_session(c);
	}

event mime_begin_entity(c: connection) &priority=10
	{
	if ( ! c?$smtp ) return;
	set_session(c, T);
	++c$smtp_mime_state$level;
	}

# This has priority -10 because other handlers need to know the current
# content_len before it's updated by this handler.
event mime_segment_data(c: connection, length: count, data: string) &priority=-10
	{
	if ( ! c?$smtp ) return;
	c$smtp_mime$content_len = c$smtp_mime$content_len + length;
	}

event mime_segment_data(c: connection, length: count, data: string) &priority=7
    {
	if ( ! c?$smtp ) return;
	if ( c$smtp_mime$content_len == 0 )
		c$smtp_mime$mime_type = split1(identify_data(data, T), /;/)[1];
	}

event mime_segment_data(c: connection, length: count, data: string) &priority=-5
	{
	if ( ! c?$smtp_mime ) return;

	if ( c$smtp_mime$content_len == 0 )
		{
		if ( generate_md5 in c$smtp_mime$mime_type )
			c$smtp_mime$calc_md5 = T;

		if ( c$smtp_mime$calc_md5 )
			{
			c$smtp_mime$calculating_md5 = T;
			md5_hash_init(c$id);
			}
		}

	if ( c$smtp_mime$calculating_md5 )
		md5_hash_update(c$id, data);
}

## In the event of a content gap during the MIME transfer, detect the state for
## the MD5 sum calculation and stop calculating the MD5 since it would be
## incorrect anyway.
event content_gap(c: connection, is_orig: bool, seq: count, length: count) &priority=5
	{
	if ( is_orig || ! c?$smtp_mime ) return;

	if ( c$smtp_mime$calculating_md5 )
		{
		c$smtp_mime$calculating_md5 = F;
		md5_hash_finish(c$id);
		}
	}

event mime_end_entity(c: connection) &priority=-3
    {
	# TODO: this check is only due to a bug in mime_end_entity that
	#       causes the event to be generated twice for the same real event.
	if ( ! c?$smtp_mime )
		return;

	if ( c$smtp_mime$calculating_md5 )
		{
		c$smtp_mime$md5 = md5_hash_finish(c$id);

		NOTICE([$note=MD5, $msg=fmt("Calculated a hash for a MIME entity from %s", c$id$orig_h),
				$sub=c$smtp_mime$md5, $conn=c]);
		}
	}

event mime_one_header(c: connection, h: mime_header_rec)
	{
	if ( ! c?$smtp ) return;
	if ( h$name == "CONTENT-DISPOSITION" &&
	          /[fF][iI][lL][eE][nN][aA][mM][eE]/ in h$value )
		c$smtp_mime$filename = sub(h$value, /^.*[fF][iI][lL][eE][nN][aA][mM][eE]=/, "");
	}

event mime_end_entity(c: connection) &priority=-5
	{
	if ( ! c?$smtp ) return;
	# This check and the delete below are just to cope with a bug where
	# mime_end_entity can be generated multiple times for the same event.
	if ( ! c?$smtp_mime )
		return;

	# Don't log anything if there wasn't any content.
	if ( c$smtp_mime$content_len > 0 )
		Log::write(SMTP_MIME, c$smtp_mime);

	delete c$smtp_mime;
	}

event mime_segment_data(c: connection, length: count, data: string) &priority=5
	{
	if ( ! c?$smtp ) return;
	if ( extract_file_types in c$smtp_mime$mime_type )
		c$smtp_mime$extract_file = T;
	}

event mime_segment_data(c: connection, length: count, data: string) &priority=3
	{
	if ( ! c?$smtp ) return;
	if ( c$smtp_mime$extract_file && c$smtp_mime$content_len == 0 )
		{
		local suffix = fmt("%d.dat", ++c$smtp_mime_state$num_extracted_files);
		local fname = generate_extraction_filename(extraction_prefix, c, suffix);
		c$smtp_mime$extraction_file = open(fname);
		enable_raw_output(c$smtp_mime$extraction_file);
		}
	}

event mime_segment_data(c: connection, length: count, data: string) &priority=-5
	{
	if ( ! c?$smtp ) return;
	if ( c$smtp_mime$extract_file && c$smtp_mime?$extraction_file )
		print c$smtp_mime$extraction_file, data;
	}

event mime_end_entity(c: connection) &priority=-3
	{
	if ( ! c?$smtp ) return;
	# TODO: this check is only due to a bug in mime_end_entity that
	#       causes the event to be generated twice for the same real event.
	if ( ! c?$smtp_mime )
		return;

	if ( c$smtp_mime?$extraction_file )
		close(c$smtp_mime$extraction_file);
	}
