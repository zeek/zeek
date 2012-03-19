# @TEST-EXEC: bro -b %INPUT >output
# @TEST-EXEC: btest-diff output

local v: vector of addr = vector();

v[|v|] = [::1];
v[|v|] = [::ffff];
v[|v|] = [::ffff:ffff];
v[|v|] = [::0a0a:ffff];
v[|v|] = [1::1];
v[|v|] = [1::a];
v[|v|] = [1::1:1];
v[|v|] = [1::1:a];
v[|v|] = [a::a];
v[|v|] = [a::1];
v[|v|] = [a::a:a];
v[|v|] = [a::a:1];
v[|v|] = [a:a::a];
v[|v|] = [aaaa:0::ffff];
v[|v|] = [::ffff:192.168.1.100];
v[|v|] = [ffff::192.168.1.100];
v[|v|] = [::192.168.1.100];
v[|v|] = [::ffff:0:192.168.1.100];
v[|v|] = [805B:2D9D:DC28::FC57:212.200.31.255];
v[|v|] = [0xaaaa::bbbb];
v[|v|] = [aaaa:bbbb:cccc:dddd:eeee:ffff:1111:2222];
v[|v|] = [aaaa:bbbb:cccc:dddd:eeee:ffff:1:2222];
v[|v|] = [aaaa:bbbb:cccc:dddd:eeee:ffff:0:2222];
v[|v|] = [aaaa:bbbb:cccc:dddd:eeee:0:0:2222];

for (i in v)
    print v[i];
