@load base/frameworks/files

module FileHash;

export {
	redef record Files::Info += {
		## A SHA1 digest of the file contents.
		sha1: string &log &optional;

		## A SHA256 digest of the file contents.
		sha256: string &log &optional;
	};

}

event file_hash(f: fa_file, kind: string, hash: string) &priority=5
	{
	switch ( kind ) {
	case "sha1":
		f$info$sha1 = hash;
		break;
	case "sha256":
		f$info$sha256 = hash;
		break;
	default: # hash for type that we do not log
		break;
	}
	}
