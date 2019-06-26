# @TEST-EXEC: zeek -b %INPUT  >output 2>&1
# @TEST-EXEC: btest-diff output

# This script tests "next" being called during the last iteration of a
# for loop

event zeek_done()
  {

        local number_set: set[count];
        local i: count;

        add number_set[0];
        add number_set[1];


        for ( i in number_set )
                {
                print fmt ("%d", i);
                if ( i == 0 )
                        next;
                print fmt ("%d", i);
                }
        print fmt ("MIDDLE");


        for ( i in number_set )
                {
                print fmt ("%d", i);
                if ( i == 1 )
                        next;
                print fmt ("%d", i);
                }
        print fmt ("THE END");

        }
