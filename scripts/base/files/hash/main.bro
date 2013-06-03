
module FilesHash;

export {
	
}

event file_hash(f: fa_file, kind: string, hash: string) &priority=5
	{
	set_info(f);
	switch ( kind ) {
	case "md5":
		f$info$md5 = hash;
		break;
	case "sha1":
		f$info$sha1 = hash;
		break;
	case "sha256":
		f$info$sha256 = hash;
		break;
	}
	}
