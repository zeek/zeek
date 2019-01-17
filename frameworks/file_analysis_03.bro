redef exit_only_after_terminate = T;

event file_new(f: fa_file)
    {
    print "new file", f$id;
    Files::add_analyzer(f, Files::ANALYZER_MD5);
    }

event file_state_remove(f: fa_file)
    {
    print "file_state_remove";
    Input::remove(f$source);
    terminate();
    }

event file_hash(f: fa_file, kind: string, hash: string)
    {
    print "file_hash", f$id, kind, hash;
    }

event bro_init()
    {
    local source: string = "./myfile";
    Input::add_analysis([$source=source, $name=source]);
    }
