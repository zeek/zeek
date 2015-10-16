# @TEST-EXEC: bro %INPUT > OUTPUT
# @TEST-EXEC: btest-diff OUTPUT

@TEST-START-FILE tags.txt
#fields	host	tag
1.2.3.4	WEB_SERVER
1.2.3.0/24	THE_NET
4.3.2.1	UNRELATED
4.0.0.0/8	MORE_UNRELATED
@TEST-END-FILE

@load base/frameworks/tagging

redef Tagging::tag_file="tags.txt";

event Tagging::read_done()
	{
	print Tagging::get(1.2.3.4);
	print Tagging::get(6.6.6.6);
	}