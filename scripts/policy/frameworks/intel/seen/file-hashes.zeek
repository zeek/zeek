@load base/frameworks/intel
@load ./where-locations

event file_hash(f: fa_file, kind: string, hash: string)
	{
	local seen = Intel::Seen($indicator=hash,
	                         $indicator_type=Intel::FILE_HASH,
	                         $f=f,
	                         $where=Files::IN_HASH);

	Intel::seen(seen);
	}