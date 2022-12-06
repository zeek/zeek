# @TEST-DOC: Call create_file_info() and populate_file_info2() when a file has been added through Input::add_analysis()

# @TEST-EXEC: zeek -b %INPUT > output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff files.log
# @TEST-EXEC: btest-diff notice.log

@load base/protocols/http
@load base/frameworks/files

redef enum Notice::Type += { NoticeTestType };

event file_new(f: fa_file)
	{
	Files::add_analyzer(f, Files::ANALYZER_SHA1);
	}

event file_hash(f: fa_file, kind: string, hash: string)
	{
	print "file_hash", kind, f?$conns ? |f$conns| : 0;
	local fi = Notice::create_file_info(f);
	print fi;
	local n: Notice::Info = Notice::Info($note=NoticeTestType, $msg="test");
	Notice::populate_file_info2(fi, n);
	NOTICE(n);
	}

event zeek_init()
	{
	Input::add_analysis([$source="./myfile", $name="./myfile"]);
	}

@TEST-START-FILE ./myfile
%PDF-1.5
This isn't an actual pdf, but it shows in files.log as such :-)
@TEST-END-FILE
