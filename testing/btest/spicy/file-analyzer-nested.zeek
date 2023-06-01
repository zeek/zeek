# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o text.hlto text.spicy ./text.evt
# @TEST-EXEC: zeek -r ${TRACES}/http/post.trace text.hlto %INPUT Spicy::enable_print=T | sort -k 3 >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: cat files.log | zeek-cut source analyzers filename mime_type >files
# @TEST-EXEC: btest-diff files
#
# Check that exceeding max-file-depth leads to aborting and an event.
# @TEST-EXEC: zeek -t /tmp/zeek.trace -r ${TRACES}/http/post.trace text.hlto %INPUT Spicy::max_file_depth=2 | sort -k 3 >output-max
# @TEST-EXEC: cat notice.log | zeek-cut note | grep -q "Spicy_Max_File_Depth_Exceeded"
# @TEST-EXEC: btest-diff output-max

event text::data1(f: fa_file, data: string)
	{
	print "data1", f$id, data;
	}

event text::data2(f: fa_file, data: string)
	{
	print "data2", f$id, data;
	}

event text::data3(f: fa_file, data: string)
	{
	print "data3", f$id, data;
	}

event Spicy::max_file_depth_exceeded(f: fa_file, args: Files::AnalyzerArgs, limit: count)
	{
	print "depth warning", f$id, args, limit;
	}

# @TEST-START-FILE text.spicy
module Text;

import zeek;
import zeek_file;

# This unit uses the zeek_file::File wrapper to pass data into Zeek's file analysis.
public type Data1 = unit {
    on %init {
        self.content.connect(new zeek_file::File("text/plain2"));
        self.content.write(b"from 1:");
        }

    data: bytes &eod -> self.content;

    sink content;
};

# This unit passes data into Zeek's file analysis directly, without the File wrapper.
public type Data2 = unit {
    data: bytes &eod {
        zeek::file_begin("text/plain3");
        zeek::file_data_in(b"from 2a:" + self.data);
        zeek::file_end();

        zeek::file_begin("text/plain3");
        zeek::file_data_in(b"from 2b:" + self.data);
        zeek::file_end();
    }
};

public type Data3 = unit {
    data: bytes &eod;
};
# @TEST-END-FILE

# @TEST-START-FILE text.evt

file analyzer spicy::Text1:
    parse with Text::Data1,
    mime-type text/plain;

file analyzer spicy::Text2:
    parse with Text::Data2,
    mime-type text/plain2;

file analyzer spicy::Text3:
    parse with Text::Data3,
    mime-type text/plain3;

on Text::Data1 -> event text::data1($file, self.data);
on Text::Data2 -> event text::data2($file, self.data);
on Text::Data3 -> event text::data3($file, self.data);
# @TEST-END-FILE
