# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -D zeek -o test.hlto doc.spicy ./doc.evt >output 2>&1
# @TEST-EXEC: cat output | grep 'module.s documentation' >output1
# @TEST-EXEC: btest-diff output1
#
# @TEST-EXEC: unset ZEEK_DISABLE_ZEEKYGEN && zeek -X zeekygen.conf test.hlto %INPUT
# @TEST-EXEC: cat protocol.rst  | sed -n '/_plugin-foo-bar/,/_plugin/p' | sed '$d' >output2
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output2
#
# @TEST-EXEC: zeek test.hlto %INPUT >output3
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output3

# @TEST-DOC: Enumeration Compression is exported in .evt file *and* defined on the Zeek side. Result in Zeekygen output is from the Zeek side. Encryption is only exported from Spicy.

module MySSH;

export {
	type Compression: enum {
		## Documentation of VERY
		VERY = 0,
		## Documentation of DIFFERENT
		DIFFERENT = 1,
	};

	# Exported from Spicy
	# type Encryption: enum { ... }
}

module GLOBAL;

event zeek_init()
	{
	# Print enum_names() of the involved types, too.
	print MySSH::Compression, enum_names(MySSH::Compression);
	print MySSH::Encryption, enum_names(MySSH::Encryption);
	}


# @TEST-START-FILE doc.spicy

module MySSH;

import zeek;

public type Compression = enum {
    NONE = 0,
    ZLIB = 1,
};

public type Encryption = enum {
    NONE = 0,
};

public type Banner = unit {
    magic   : /SSH-/;
    version : /[^-]*/;
    dash    : /-/;
    software: /[^\r\n]*/;
};
# @TEST-END-FILE

# @TEST-START-FILE doc.evt

%doc-id = Foo::Bar;
%doc-description = "Just a \"test\" analyzer.h";

protocol analyzer spicy::MySSH over TCP:
    parse originator with MySSH::Banner,
    port 22/tcp,
    replaces SSH;

export MySSH::Compression;  # This one also exists on the Zeek side

export MySSH::Encryption;


# @TEST-END-FILE

# @TEST-START-FILE zeekygen.conf
proto_analyzer	*	protocol.rst

