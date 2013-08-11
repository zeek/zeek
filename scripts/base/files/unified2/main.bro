


event file_new(f: fa_file)
	{
	print "found a file";
	print f$mime_type;
	print Files::add_analyzer(f, Files::ANALYZER_UNIFIED2);
	}

event unified2_alert(f: fa_file, alert: count)
	{
	print "yaayyaya!!!";

	print alert;
	}