event file_new(f: fa_file)
    {
    print "new file", f$id;
    if ( f?$mime_type && f$mime_type == "text/plain" )
        Files::add_analyzer(f, Files::ANALYZER_MD5);
    }

event file_hash(f: fa_file, kind: string, hash: string)
    {
    print "file_hash", f$id, kind, hash;
    }
