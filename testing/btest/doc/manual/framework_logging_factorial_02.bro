# @TEST-EXEC: bro %INPUT
# @TEST-EXEC: btest-diff factor.log

module Factor;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        num:           count &log;
        factorial_num: count &log;
        };
    }

function factorial(n: count): count
    {
    if ( n == 0 )
        {
        return 1;
        }
    else
        {
        return ( n * factorial(n - 1) );
        }
    }

    
event bro_init()
    {
    local numbers: vector of count = vector(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);

    Log::create_stream(LOG, [$columns=Info]);
    
    for ( n in numbers )
        {
        Log::write( Factor::LOG, [$num=numbers[n],
                                  $factorial_num=factorial(numbers[n])]);
        }
    }


