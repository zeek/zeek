# Needs perftools support.
#
# @TEST-REQUIRES: zeek  --help 2>&1 | grep -q mem-leaks
#
# @TEST-GROUP: leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run zeek zeek -m -r $TRACES/http/get.trace $SCRIPTS/file-analysis-test.zeek %INPUT
# @TEST-EXEC: btest-bg-wait 120

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
    return function (c: count): count
        {
        return one(two(c));
        };
    }

function make_dog(name: string, weight: count) : function(i: string, item: string)
    {
    return function(i: string, item: string)
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

event new_connection(c: connection)
    {
    local v = vector(vector(1, 2, 3), vector(4, 5, 6));

    local make_laster = function(start: count) : function(i: count): count
        {
        return function(i: count): count
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

    # things like this are only possible becuse we allow functions to
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
        mfs += function() { print i, vs[i]; };
        }
    for ( i in mfs)
        mfs[i]();
    }
