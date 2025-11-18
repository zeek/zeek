# @TEST-DOC: Verify the files.log mat when Input::add_analysis() The fields info$id and info$uid are not expected to be set.
# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace $SCRIPTS/file-analysis-test.zeek %INPUT
# @TEST-EXEC: btest-diff files.log

@load base/frameworks/files

redef exit_only_after_terminate=T;

event zeek_init()
	{
	local source: string = "./myfile";
	Input::add_analysis([$source=source, $name=source]);
	}

event file_new(f: fa_file)
	{
	terminate();
	}

# @TEST-START-FILE ./myfile
%PDF-1.5
This isn't an actual pdf, but it shows in files.log as such :-)
# @TEST-END-FILE
