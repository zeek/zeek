type Idx: record {
    host: addr;
};

type Val: record {
    users: set[string];
};

global hostslist: table[addr] of Val = table();

event bro_init()
    {
    Input::add_table([$source="/var/db/hosts",
        $name="hosts",
        $idx=Idx,
        $val=Val,
        $destination=hostslist,
        $reader=Input::READER_SQLITE,
        $config=table(["query"] = "select * from machines_to_users;")
        ]);

    Input::remove("hosts");
    }

event Input::end_of_data(name: string, source: string)
    {
    if ( name != "hosts" )
        return;

    # now all data is in the table
    print "Hosts list has been successfully imported";

    # List the users of one host.
    print hostslist[192.168.17.1]$users;
    }
