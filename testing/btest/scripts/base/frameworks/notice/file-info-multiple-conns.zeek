# @TEST-DOC: Call create_file_info() and populate_file_info2() when a file is transferred over multiple connections.

# @TEST-EXEC: zeek -b %INPUT -r $TRACES/http/concurrent-range-requests-complete.pcap > output
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
