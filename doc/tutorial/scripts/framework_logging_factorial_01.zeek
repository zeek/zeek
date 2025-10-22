module Factor;

function factorial(n: count): count
    {
    if ( n == 0 )
        return 1;
    else
        return ( n * factorial(n - 1) );
    }

event zeek_init()
    {
    local numbers: vector of count = vector(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
    
    for ( n in numbers )
        print fmt("%d", factorial(numbers[n]));
    }


