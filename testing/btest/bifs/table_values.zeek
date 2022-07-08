#
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local t = table(
        ["web"] = { [80/tcp, "http"], [443/tcp, "https"] },
        ["login"] = { [21/tcp, "ftp"], [23/tcp, "telnet"] }
    );

    local v: vector of set[port, string] = table_values(t);

    for ( i in v )
        {
        print v[i];
        }
	}