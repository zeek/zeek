@load policy/protocols/ssh/interesting-hostnames.zeek
@load base/protocols/ssh/

redef Notice::emailed_types += {
    SSH::Interesting_Hostname_Login
};

