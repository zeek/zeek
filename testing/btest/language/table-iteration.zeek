# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

global tbl: table[count] of count;
global tbl2: table[count] of count &ordered;

event zeek_init()
{
    local i = 0;
    while ( i < 3 )
    {
       ++i;
       tbl[i] = i;
       tbl2[i] = i;
    }

    for ( [k], v in tbl )
    {
       print(v);
    }

    for ( [k], v in tbl2 )
    {
       print(v);
    }
}
