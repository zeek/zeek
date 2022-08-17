# @TEST-DOC: Verify the files.log mat when Input::add_analysis() The fields info$id and info$uid are not expected to be set.
# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace $SCRIPTS/file-analysis-test.zeek %INPUT
# @TEST-EXEC: btest-diff files.log

@load base/frameworks/files

event zeek_init()
	{
	local source: string = "./myfile";
	Input::add_analysis([$source=source, $name=source]);
	}

@TEST-START-FILE ./myfile
%PDF-1.5
This isn't an actual pdf, but it shows in files.log as such :-)
@TEST-END-FILE
