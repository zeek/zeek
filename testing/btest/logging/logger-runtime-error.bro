#
# @TEST-EXEC: bro %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

global a: table[count] of count;

event bro_init()
{
    print a[2];
}

print a[1];

