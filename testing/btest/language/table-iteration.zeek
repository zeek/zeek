# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

global tbl: table[count] of count;
global tbl2: table[count] of count &ordered;
global tbl3: table[count] of count = {
    [4] = 4,
    [5] = 5,
} &ordered &redef;

redef tbl3 += { [6] = 6 };

event zeek_init()
{
    local i = 0;
    while ( i < 3 )
    {
       ++i;
       tbl[i] = i;
       tbl2[i] = i;
       tbl3[i] = i;
    }

    print "tbl";
    for ( [k], v in tbl )
    {
       print(v);
    }

    print "tbl2";
    for ( [k], v in tbl2 )
    {
       print(v);
    }

    print "tbl3";
    for ( [k], v in tbl3 )
    {
       print(v);
    }
}
