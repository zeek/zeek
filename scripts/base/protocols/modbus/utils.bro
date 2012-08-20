
#this function checks if the function code is exception (ie. normal fc are 1-127, exception codes are >127)
# e.g, fc=128 implies exception repsonse for fc=1
function check_e(a:count):count
{
        if (a>127) a=a-128;
        return a;
}

