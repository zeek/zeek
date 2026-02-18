# @TEST-DOC: Verify analyzer_violation_info is raised for an invalid PE file.
# TODO: This test hangs indefinitely on Windows and is skipped for the time being.
# @TEST-REQUIRES: ! is-windows
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff .stderr
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: btest-diff files.log

@load base/frameworks/files
@load base/files/pe

redef exit_only_after_terminate = T;

event analyzer_violation_info(tag: AllAnalyzers::Tag, info: AnalyzerViolationInfo)
	{
	print tag, info$reason, info$f$id, cat(info$f$info$analyzers);
	terminate();
	}

event force_terminate()
	{
	if ( zeek_is_terminating() )
		return;

	Reporter::error("force_terminate called - timeout?");
	terminate();
	}

event zeek_init()
	{
	local source: string = "./myfile.exe";
	Input::add_analysis([$source=source, $name=source]);
	schedule 10sec { force_terminate() };
	}

# This file triggers a binpac exception for PE that is reported through
# analyzer_violation_info
# @TEST-START-FILE ./myfile.exe
MZ0000000000000000000000000000000000000000000000000000000000000
# @TEST-END-FILE
