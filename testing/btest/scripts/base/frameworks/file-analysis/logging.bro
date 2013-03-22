# @TEST-EXEC: bro -r $TRACES/http/get.trace $SCRIPTS/file-analysis-test.bro %INPUT
# @TEST-EXEC: btest-diff file_analysis.log

redef test_file_analysis_source = "HTTP";

redef test_get_file_name = function(info: FileAnalysis::Info): string
    {
    return fmt("%s-file", info$file_id);
    };
