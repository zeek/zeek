# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o test.hlto text.spicy ./text.evt
# @TEST-EXEC: zeek -r ${TRACES}/http/post.trace test.hlto %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff weird.log

event zeek_init()
	{
	# Check we can access the tag.
	print Files::ANALYZER_SPICY_TEXT;
	}

event text::data(f: fa_file, data: string)
	{
	print "text data", f$id, data;
	}

# @TEST-START-FILE text.spicy
module Text;

import zeek;

public type Data = unit {
    data: bytes &eod;

    on %done {
        # File ID isn't stable across platforms, so just check expected length.
        assert |zeek::fuid()| == 18;
        zeek::weird("test_weird");
    }
};
# @TEST-END-FILE

# @TEST-START-FILE text.evt

file analyzer spicy::Text:
    parse with Text::Data,

    # Note that Zeek determines the MIME type not from the Content-Type
    # header in the trace, but by content sniffing (i.e., libmagic-style)
    mime-type text/plain;
    #mime-type application/x-www-form-urlencoded;

on Text::Data -> event text::data($file, self.data);
# @TEST-END-FILE
