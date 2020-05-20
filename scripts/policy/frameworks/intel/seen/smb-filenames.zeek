@load base/protocols/smb
@load base/frameworks/intel
@load ./where-locations

event file_new(f: fa_file)
    {
    if ( f$source != "SMB" )
        return;

    for ( id in f$conns )
        {
        local c = f$conns[id];
        if ( c?$smb_state && c$smb_state?$current_file && c$smb_state$current_file?$name )
            {
            local split_fname = split_string(c$smb_state$current_file$name, /\\/);
            local fname = split_fname[|split_fname|-1];
            Intel::seen([$indicator=fname,
                        $indicator_type=Intel::FILE_NAME,
                        $f=f,
                        $where=SMB::IN_FILE_NAME]);
            }
        }
    }
