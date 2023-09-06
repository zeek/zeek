# @TEST-EXEC: zeek -C -b -r $TRACES/http/http-large-gap.pcap %INPUT efname=1 FileExtract::default_limit_includes_missing=T
# @TEST-EXEC: btest-diff --binary extract_files/1
# @TEST-EXEC: btest-diff 1.out
# @TEST-EXEC: mv files.log files-1.log
# @TEST-EXEC: btest-diff files-1.log
# @TEST-EXEC: zeek -C -b -r $TRACES/http/http-large-gap.pcap %INPUT efname=2 FileExtract::default_limit_includes_missing=F
# @TEST-EXEC: rm extract_files/2
# @TEST-EXEC: btest-diff 2.out
# @TEST-EXEC: mv files.log files-2.log
# @TEST-EXEC: btest-diff files-2.log
# @TEST-EXEC: zeek -C -b -r $TRACES/http/http-large-gap.pcap %INPUT efname=3 FileExtract::default_limit_includes_missing=F max_extract=1
# @TEST-EXEC: rm extract_files/3
# @TEST-EXEC: btest-diff 3.out
# @TEST-EXEC: mv files.log files-3.log
# @TEST-EXEC: btest-diff files-3.log

@load base/files/extract
@load base/protocols/http

global outfile: file;
const max_extract: count = 10 &redef;
const efname: string = "0" &redef;

event file_new(f: fa_file)
    {
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT,
	                    [$extract_filename=efname, $extract_limit=max_extract]);
    }

event file_extraction_limit(f: fa_file, args: any, limit: count, len: count)
    {
    print outfile, "file_extraction_limit", limit, len;
    }

event zeek_init()
	{
	outfile = open(fmt("%s.out", efname));
	}
