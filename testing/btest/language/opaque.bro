
# @TEST-EXEC: bro %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

global obj: test_object;
global t: table[count] of test_object;

obj = create_test_object();

do_something_with_test_object(obj);

obj = create_test_object();

t[1] = obj;
print t;
delete t[1];

obj = create_test_object();
