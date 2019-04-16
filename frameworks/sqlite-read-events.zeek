@load frameworks/files/hash-all-files

type Val: record {
    hash: string;
    description: string;
};

event line(description: Input::EventDescription, tpe: Input::Event, r: Val)
    {
    print fmt("malware-hit with hash %s, description %s", r$hash, r$description);
    }

global malware_source = "/var/db/malware";

event file_hash(f: fa_file, kind: string, hash: string)
    {

    # check all sha1 hashes
    if ( kind=="sha1" )
        {
        Input::add_event(
            [
            $source=malware_source,
            $name=hash,
            $fields=Val,
            $ev=line,
            $want_record=T,
            $config=table(
                ["query"] = fmt("select * from malware_hashes where hash='%s';", hash)
                ),
            $reader=Input::READER_SQLITE
            ]);
        }
    }

event Input::end_of_data(name: string, source:string)
    {
    if ( source == malware_source )
        Input::remove(name);
    }
