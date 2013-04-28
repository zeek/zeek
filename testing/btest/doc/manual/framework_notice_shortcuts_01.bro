# @TEST-EXEC: bro %INPUT
# @TEST-EXEC: btest-diff .stdout

@load policy/protocols/ssh/interesting-hostnames.bro
@load base/protocols/ssh/

redef Notice::emailed_types += {
    SSH::Interesting_Hostname_Login,
    SSH::Login
};

