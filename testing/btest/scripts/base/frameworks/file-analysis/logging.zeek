# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace $SCRIPTS/file-analysis-test.zeek %INPUT
# @TEST-EXEC: btest-diff files.log

@load base/protocols/http

redef test_file_analysis_source = "HTTP";

redef test_get_file_name = function(f: fa_file): string
    {
    return fmt("%s-file", f$id);
    };
