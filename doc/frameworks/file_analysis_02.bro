event file_mime_type(f: fa_file, mime_type: string)
    {
    print "new file", f$id;
    if ( mime_type == "text/plain" )
        Files::add_analyzer(f, Files::ANALYZER_MD5);
    }

event file_hash(f: fa_file, kind: string, hash: string)
    {
    print "file_hash", f$id, kind, hash;
    }
