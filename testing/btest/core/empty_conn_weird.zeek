#
# @TEST-EXEC: zeek -b %INPUT

event zeek_init()
{
        local x: connection;
        x$uid = "uid";
        
        Reporter::conn_weird("foo", x);
        print "done";
}
