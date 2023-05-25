# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o test.hlto ssh.spicy ./ssh-cond.evt
# @TEST-EXEC: zeek -r ${TRACES}/ssh/single-conn.trace test.hlto %INPUT | sort  >output
# @TEST-EXEC: btest-diff output

event ssh::banner1(c: connection, is_orig: bool, version: string, software: string)
	{
	print "1", software;
	}

event ssh::banner2(c: connection, is_orig: bool, version: string, software: string)
	{
	print "2", software;
	}

event ssh::banner3(c: connection, is_orig: bool, version: string, software: string)
	{
	print "3", software;
	}

event ssh::banner4(c: connection, is_orig: bool, version: string, software: string)
	{
	print "4", software;
	}

event ssh::banner5(c: connection, is_orig: bool, version: string, software: string)
	{
	print "5", software;
	}

# @TEST-START-FILE ssh.spicy
module SSH;

public type Banner = unit {
    magic   : /SSH-/;
    version : /[^-]*/;
    dash    : /-/;
    software: /[^\r\n]*/;
};
# @TEST-END-FILE

# @TEST-START-FILE ssh-cond.evt

import zeek;

protocol analyzer spicy::SSH over TCP:
    parse with SSH::Banner,
    port 22/tcp,
    replaces SSH;

on SSH::Banner if ( True ) -> event ssh::banner1($conn, $is_orig, self.version, self.software);
on SSH::Banner if ( False )-> event ssh::banner2($conn, $is_orig, self.version, self.software);
on SSH::Banner if ( self.software == b"OpenSSH_3.9p1" )-> event ssh::banner3($conn, $is_orig, self.version, self.software);
on SSH::Banner if ( self.software != b"OpenSSH_3.9p1" )-> event ssh::banner4($conn, $is_orig, self.version, self.software);
on SSH::Banner if ( zeek::is_orig() ) -> event ssh::banner5($conn, $is_orig, self.version, self.software);

# @TEST-END-FILE
