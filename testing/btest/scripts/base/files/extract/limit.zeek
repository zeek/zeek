# @TEST-EXEC: zeek -b -r $TRACES/ftp/retr.trace %INPUT max_extract=3000 efname=1
# @TEST-EXEC: btest-diff extract_files/1
# @TEST-EXEC: btest-diff 1.out
# @TEST-EXEC: zeek -b -r $TRACES/ftp/retr.trace %INPUT max_extract=3000 efname=2 double_it=T
# @TEST-EXEC: btest-diff extract_files/2
# @TEST-EXEC: btest-diff 2.out
# @TEST-EXEC: btest-diff files.log
# @TEST-EXEC: zeek -b -r $TRACES/ftp/retr.trace %INPUT max_extract=7000 efname=3 unlimit_it=T
# @TEST-EXEC: btest-diff extract_files/3
# @TEST-EXEC: btest-diff 3.out

@load base/files/extract
@load base/protocols/ftp

global outfile: file;
const max_extract: count = 0 &redef;
const double_it: bool = F &redef;
const unlimit_it: bool = F &redef;
const efname: string = "0" &redef;
global doubled: bool = F;

event file_new(f: fa_file)
    {
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT,
	                    [$extract_filename=efname, $extract_limit=max_extract]);
    }

event file_extraction_limit(f: fa_file, args: any, limit: count, len: count)
    {
    print outfile, "file_extraction_limit", limit, len;

	if ( double_it && ! doubled )
		{
		doubled = T;
		print outfile, FileExtract::set_limit(f, args, max_extract*2);
		}

	if ( unlimit_it )
		print outfile, FileExtract::set_limit(f, args, 0);
    }

event zeek_init()
	{
	outfile = open(fmt("%s.out", efname));
	}
