module Factor;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        num:           count &log;
        factorial_num: count &log;
        };
    
    global log_factor: event(rec: Info);
    }

function factorial(n: count): count
    {
    if ( n == 0 )
        return 1;
    
    else
        return (n * factorial(n - 1));
    }

event bro_init()
    {
    Log::create_stream(LOG, [$columns=Info, $ev=log_factor]);
    }

event bro_done()
    {
    local numbers: vector of count = vector(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);    
    for ( n in numbers )
        Log::write( Factor::LOG, [$num=numbers[n],
                                  $factorial_num=factorial(numbers[n])]);
    }

function mod5(id: Log::ID, path: string, rec: Factor::Info) : string    
    {
    if ( rec$factorial_num % 5 == 0 )
        return "factor-mod5";
    
    else
        return "factor-non5";
    }

event bro_init()
    {
    local filter: Log::Filter = [$name="split-mod5s", $path_func=mod5];
    Log::add_filter(Factor::LOG, filter);
    Log::remove_filter(Factor::LOG, "default");
    }
