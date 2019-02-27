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
            Intel::seen([$indicator=c$smb_state$current_file$name,
                        $indicator_type=Intel::FILE_NAME,
                        $f=f,
                        $where=Files::IN_NAME]);
            }
        }
    }