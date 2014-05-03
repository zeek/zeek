@load policy/protocols/ssh/interesting-hostnames.bro
@load base/protocols/ssh/

redef Notice::type_suppression_intervals += {
    [SSH::Interesting_Hostname_Login] = 1day,
    [SSH::Login] = 12hrs,
};
