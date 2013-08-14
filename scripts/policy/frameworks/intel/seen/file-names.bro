@load base/frameworks/intel
@load ./where-locations

event file_new(f: fa_file)
	{
	if ( f?$info && f$info?$filename )
		Intel::seen([$indicator=f$info$filename,
		             $indicator_type=Intel::FILE_NAME,
		             $f=f,
		             $where=Files::IN_NAME]);
	}