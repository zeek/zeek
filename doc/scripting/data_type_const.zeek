const port_list: table[port] of string &redef;

redef port_list += { [6666/tcp] = "IRC"};
redef port_list += { [80/tcp] = "WWW" };

event zeek_init()
    {
    print port_list;
    }
