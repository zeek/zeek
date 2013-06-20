# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

const foo: vector of double = vector( 21.0, 11.0, 8.0 ) &redef;

redef foo += vector(42.0, 44.0, 50.0);
redef foo += { 88.0, 99.0, 101.0 };
redef foo += { 0.0 };
redef foo += vector();
redef foo += { };

print foo;
