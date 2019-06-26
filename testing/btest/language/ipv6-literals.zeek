# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

local v: vector of addr = vector();

v += [::1];
v += [::ffff];
v += [::ffff:ffff];
v += [::0a0a:ffff];
v += [1::1];
v += [1::a];
v += [1::1:1];
v += [1::1:a];
v += [a::a];
v += [a::1];
v += [a::a:a];
v += [a::a:1];
v += [a:a::a];
v += [aaaa:0::ffff];
v += [::ffff:192.168.1.100];
v += [ffff::192.168.1.100];
v += [::192.168.1.100];
v += [::ffff:0:192.168.1.100];
v += [805B:2D9D:DC28::FC57:212.200.31.255];
v += [0xaaaa::bbbb];
v += [aaaa:bbbb:cccc:dddd:eeee:ffff:1111:2222];
v += [aaaa:bbbb:cccc:dddd:eeee:ffff:1:2222];
v += [aaaa:bbbb:cccc:dddd:eeee:ffff:0:2222];
v += [aaaa:bbbb:cccc:dddd:eeee:0:0:2222];

for (i in v)
    print v[i];
