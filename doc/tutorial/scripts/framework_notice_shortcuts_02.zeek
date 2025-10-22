@load policy/protocols/ssh/interesting-hostnames.zeek
@load base/protocols/ssh/

redef Notice::type_suppression_intervals += {
    [SSH::Interesting_Hostname_Login] = 1day,
};
