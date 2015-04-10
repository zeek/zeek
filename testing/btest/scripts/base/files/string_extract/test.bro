# @TEST-EXEC: bro -r $TRACES/http/bro.org.pcap %INPUT >out1
# @TEST-EXEC: bro -r $TRACES/http/bro.org.pcap %INPUT "mylimit=8" >out2
# @TEST-EXEC: btest-diff out1
# @TEST-EXEC: btest-diff out2

const mylimit: count = 0 &redef;

event myextraction(f: fa_file, data: string)
	{
	print "string extracted", data;
	}

event file_new(f: fa_file)
	{
	Files::add_analyzer(f, Files::ANALYZER_STRINGEXTRACT, 
	                    [$string_extract_limit=mylimit, 
	                     $string_extract_event=myextraction,
	                     $string_extract_preamble="<title>",
	                     $string_extract_postamble="</title>"]);
	}
