# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o test.hlto text.spicy ./text.evt
# @TEST-EXEC: zeek -r ${TRACES}/http/post.trace test.hlto %INPUT >output
# @TEST-EXEC: btest-diff output

event text::data(f: fa_file, data: string)
	{
	print "text data", f$id, data;
	}

# @TEST-START-FILE text.spicy
module Text;

public type Data = unit {
    %mime-type = "text/plain";
    data: bytes &eod;
};
# @TEST-END-FILE

# @TEST-START-FILE text.evt

file analyzer spicy::Text:
    parse with Text::Data;

on Text::Data -> event text::data($file, self.data);
# @TEST-END-FILE
