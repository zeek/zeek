# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o foo.hlto foo.spicy foo.evt
# @TEST-EXEC: zeek -r ${TRACES}/ssh/single-conn.trace foo.hlto %INPUT Spicy::enable_print=T >output
# @TEST-EXEC: btest-diff output

# @TEST-START-FILE foo.spicy
module foo;
import zeek;

public type X = unit {
    xs: bytes &eod {
	local y = zeek::protocol_handle_get_or_create("spicy_Y");
	local z = zeek::protocol_handle_get_or_create("spicy_Z");

	zeek::protocol_data_in(zeek::is_orig(), b"only Y", y);
	zeek::protocol_data_in(zeek::is_orig(), b"both Y and Z");

	zeek::protocol_handle_close(z);
	zeek::protocol_data_in(zeek::is_orig(), b"only Y after removal of Z");

	zeek::protocol_handle_close(y);
	zeek::protocol_data_in(zeek::is_orig(), b"goes nowhere");
    }
};

public type Y = unit {
    ys: bytes &eod &chunked { print "ys=%s" % $$; }
};

public type Z = unit {
    zs: bytes &eod &chunked { print "zs=%s" % $$; }
};
# @TEST-END-FILE

# @TEST-START-FILE foo.evt
# Analyzer instantiated from Zeek based on the traffic.
protocol analyzer spicy::X over TCP:
    parse originator with foo::X,
    port 22/tcp,
    replaces SSH;

# Analyzers which will only be instantiated explicitly by us.
protocol analyzer spicy::Y over TCP:
    parse originator with foo::Y;
protocol analyzer spicy::Z over TCP:
    parse originator with foo::Z;
# @TEST-END-FILE
