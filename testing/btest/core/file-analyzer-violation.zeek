# @TEST-DOC: Verify analyzer_violation_info is raised for an invalid PE file.
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: btest-diff files.log

@load base/frameworks/files
@load base/files/pe

event analyzer_violation_info(tag: AllAnalyzers::Tag, info: AnalyzerViolationInfo)
	{
	print tag, info$reason, info$f$id, cat(info$f$info$analyzers);
	}

event zeek_init()
	{
	local source: string = "./myfile.exe";
	Input::add_analysis([$source=source, $name=source]);
	}

# This file triggers a binpac exception for PE that is reported through
# analyzer_violation_info
@TEST-START-FILE ./myfile.exe
MZ0000000000000000000000000000000000000000000000000000000000000
@TEST-END-FILE
