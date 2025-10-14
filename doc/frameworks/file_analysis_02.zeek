event file_sniff(f: fa_file, meta: fa_metadata)
    {
	if ( ! meta?$mime_type ) return;
    print "new file", f$id;
    if ( meta$mime_type == "text/plain" )
        Files::add_analyzer(f, Files::ANALYZER_MD5);
    }

event file_hash(f: fa_file, kind: string, hash: string)
    {
    print "file_hash", f$id, kind, hash;
    }
