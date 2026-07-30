# @TEST-EXEC-FAIL: zeek -b %INPUT  >output 2>&1
# @TEST-EXEC: btest-diff-remove-abspath output

global a: count &add_func = function(old: count, new: count): count { return 3; };
global b: count &delete_func = function(old: count, new: count): count { return 3; };

redef a += 13;
redef b -= 13;

# The following is ok.
global c: count &redef &add_func = function(old: count, new: count): count { return 3; };
redef c = 0;
redef c += 13;


