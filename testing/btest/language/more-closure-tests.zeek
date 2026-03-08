# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

redef exit_only_after_terminate = T;

# maps a function to a vector
function map_1 (f: function(a: count): count, v: vector of count) : vector of count
    {
    local out: vector of count;

    for ( i in v )
        out += f(v[i]);

    return out;
    }

# stacks two functions
function stacker (one : function(a: count): count, two: function (b: count): count): function(c: count): count
    {
    return function [one,two](c: count): count
        {
        return one(two(c));
        };
    }

function make_dog(name: string, weight: count) : function(i: string, item: string)
    {
    return function[name, weight](i: string, item: string)
        {
        switch i
            {
            case "set name":
                name = item;
                break;
            case "get name":
                print name;
                break;
            case "eat":
                print ++weight;
                break;
            case "run":
                print --weight;
                break;
            default:
                print "bark";
                break;
            }
        };
    }

function die()
    {
    local h: addr = 127.0.0.1;

	when [h] ( local hname = lookup_addr(h) )
		{
		print "lookup successful";
		terminate();
		}
	timeout 10sec
		{
		print "timeout (1)";
		}
    }

event zeek_init()
    {
    local v = vector(vector(1, 2, 3), vector(4, 5, 6));

    local make_laster = function(start: count) : function(i: count): count
        {
        return function[start](i: count): count
            {
            local temp = i;
            i += start;
            start = temp;
            return i;
            };
        };

    local test = vector(1, 2, 3);
    print "expect [1, 3, 5]";
    print map_1(make_laster(0), test);

    local times_two = function(i: count): count { return i*2; };
    local times_four = stacker(times_two, times_two);
    local times_eight = stacker(times_four, times_two);

    print "expect 16";
    print times_eight(2);

    print "expect [8, 16, 24]";
    print map_1(times_eight, test);

    # things like this are only possible because we allow functions to
    # mutate their closures.
    local thunder= make_dog("thunder", 10);
    thunder("get name", "");
    thunder("set name", "buster");
    thunder("get name", "");
    thunder("eat", "");
    thunder("eat", "");
    thunder("run", "");


    # why this works is a little bit of a mystery to me.
    # I suspect it has something to do with how for loops handle frames.
    # the above test shows that we are properly capturing primitives
    # by reference.
    local mfs: vector of function();
    local vs = vector("dog", "cat", "fish");
    for (i in vs)
        {
        mfs += function[i, vs]() { print i, vs[i]; };
        }
    for ( i in mfs)
        mfs[i]();

    die();
    }
